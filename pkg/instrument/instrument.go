package instrument

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/CoverConnect/ego/internal"
	"github.com/CoverConnect/ego/pkg/disassembler"
	"github.com/backman-git/delve/pkg/proc"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var in *Instrument

const (
	LOG_LEVEL  = slog.LevelDebug
	LOG_ARG    = true
	LOG_RETURN = true
)

var (
	TRACE_FUNC = true
)

func init() {

	// Init instrument library
	exec, err := os.Executable()
	if err != nil {
		log.Printf("Fail to load exec file. path:%s", exec)
		return
	}

	in = NewInstrument(exec)
	in.Start()

	slog.SetLogLoggerLevel(LOG_LEVEL)
	slog.Debug("Instrument Ready")
}

type Instrument struct {
	hookObj *hookObjects
	bi      *proc.BinaryInfo
	ex      *link.Executable

	userProbes map[string][]*userProbe // function prefix -> userProbe

	binaryPath      string
	FunctionManager *internal.FunctionManager
}

type userProbe struct {
	start link.Link
	end   []link.Link
}

func NewInstrument(binaryPath string) *Instrument {

	//use ebpf
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load hook eBPF into kernel
	var hookObj hookObjects
	if err := loadHookObjects(&hookObj, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		log.Fatalf("load program %v", err)
	}

	// load binary use delve
	bi := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
	if err := bi.LoadBinaryInfo(binaryPath, 0, nil); err != nil {
		log.Fatal(err)
	}

	// open program to probe
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		log.Fatalf("open exec fail %w", err)
	}

	return &Instrument{bi: bi, binaryPath: binaryPath, hookObj: &hookObj, ex: ex, FunctionManager: internal.NewFunctionManager()}
}

func GetInstrument() *Instrument {
	return in
}

func (i Instrument) Start() error {

	// go collector
	go ReadPerf(i.hookObj.hookMaps.ProbeTimeEvent, CtxChan)
	go func() {
		debug.SetPanicOnFault(true)
		Collect(i.bi, CtxChan)
	}()

	return nil
}

func (i Instrument) Stop() {

	for _, probes := range i.userProbes {
		for _, probe := range probes {
			probe.start.Close()
			for _, endProbe := range probe.end {
				endProbe.Close()
			}
		}
	}

	defer i.hookObj.Close()

}

func (i *Instrument) ProbeFunctionWithPrefix(prefix string) {
	// TODO move to instrument type
	goidOffset, err := getGoIDOffset(i.bi)
	if err != nil {
		slog.Debug("%+v\n", err)
		return
	}

	parentGoidOffset, err := getParentIDOffset(i.bi)
	if err != nil {
		slog.Debug("%+v\n", err)
		return
	}

	// heavy depend on the platform
	gOffset, err := i.bi.GStructOffset(nil)
	if err != nil {
		slog.Debug("%+v\n", err)
		return
	}

	// Probe the function with all signature
	userProbes := make(map[string][]*userProbe)
	for _, f := range GetFunctionByPrefix(i.bi, prefix) {

		params, err := GetFunctionParameter(i.bi, f, f.Entry, false)
		if err != nil {
			slog.Debug("Can't get params of function args", "error", err)
			return
		}

		if err := sendParamToHook(i.hookObj, f.Entry, params, goidOffset, parentGoidOffset, gOffset, false); err != nil {
			slog.Debug("send param to ebpf", "error", err)
			return
		}

		// uprobe to function (trace)
		up, err := i.ex.Uprobe(f.Name, i.hookObj.UprobeHook, nil)
		if err != nil {
			slog.Debug("set uprobe error: %v", err)
			continue
		}

		userProbe := &userProbe{start: up, end: make([]link.Link, 0)}
		slog.Debug("uprobe", "fname", f.Name)

		//uprobe to function end
		// refer from delve

		instructions, err := disassembler.Decode(f.Entry, f.End)
		if err != nil {
			slog.Debug("Decode Function", "Error", err)
			userProbes[prefix] = append(userProbes[prefix], userProbe)
			continue
		}

		var addrs []uint64
		for _, instruction := range instructions {
			if instruction.IsRet() {
				addrs = append(addrs, instruction.Loc.PC)
			}
		}
		addrs = append(addrs, proc.FindDeferReturnCalls(instructions)...)
		for _, addr := range addrs {
			retParams, err := GetFunctionParameter(i.bi, f, addr, true)
			if err != nil {
				slog.Debug("Can't get ret Params", "Error", err)
				continue
			}

			// no matter what, we need to send the ret params to ebpf
			if err := sendParamToHook(i.hookObj, addr, retParams, goidOffset, parentGoidOffset, gOffset, true); err != nil {
				slog.Debug("send ret params to ebpf", "error", err)
				continue
			}

			off := getRelatedOffset(f.Entry, addr)
			end, err := i.ex.Uprobe(f.Name, i.hookObj.UprobeHook, &link.UprobeOptions{Offset: off})
			if err != nil {
				slog.Debug("set uretprobe", "error", err)
				return
			}
			userProbe.end = append(userProbe.end, end)
			slog.Debug("set uretprobe:", "fname", f.Name, "addr", addr, "offset", off)

		}
		userProbes[prefix] = append(userProbes[prefix], userProbe)
	}
	i.userProbes = userProbes
}

func (i *Instrument) UnProbeFunctionWithPrefix(prefix string) {
	for _, probe := range i.userProbes[prefix] {
		probe.start.Close()
		for _, endProbe := range probe.end {
			endProbe.Close()
		}
	}
}

func getRelatedOffset(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
