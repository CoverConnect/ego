package instrument

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

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
	LOG_METRIC = true
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

	userProbes map[string]*userProbe // function prefix -> userProbe

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

	return &Instrument{bi: bi, binaryPath: binaryPath, hookObj: &hookObj, ex: ex, FunctionManager: internal.NewFunctionManager(), userProbes: make(map[string]*userProbe)}
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

	for _, probe := range i.userProbes {
		probe.start.Close()
		for _, endProbe := range probe.end {
			endProbe.Close()
		}

	}

	defer i.hookObj.Close()

}

func (i *Instrument) ProbeFunctionWithPrefix(prefix string) []string {

	probedFuncs := make([]string, 0)

	// TODO move to instrument type
	goidOffset, err := getGoIDOffset(i.bi)
	if err != nil {
		slog.Debug("%+v\n", err)
		return probedFuncs
	}

	parentGoidOffset, err := getParentIDOffset(i.bi)
	if err != nil {
		slog.Debug("%+v\n", err)
		return probedFuncs
	}

	// heavy depend on the platform
	gOffset, err := i.bi.GStructOffset(nil)
	if err != nil {
		slog.Debug("%+v\n", err)
		return probedFuncs
	}

	// Probe the function with all signature
	for _, f := range GetFunctionByPrefix(i.bi, prefix) {

		params, err := GetFunctionParameter(i.bi, f, f.Entry, false)
		if err != nil {
			slog.Debug("Can't get params of function args", "error", err)
			continue
		}

		if err := sendParamToHook(i.hookObj, f.Entry, params, goidOffset, parentGoidOffset, gOffset, false); err != nil {
			slog.Debug("send param to ebpf", "error", err)
			continue
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
				continue
			}
			userProbe.end = append(userProbe.end, end)
			slog.Debug("set uretprobe:", "fname", f.Name, "addr", addr, "offset", off)

		}
		i.userProbes[f.Name] = userProbe
		probedFuncs = append(probedFuncs, f.Name)
	}

	return probedFuncs
}

func (i *Instrument) UnProbeFunctionWithPrefix(prefix string) []string {
	unprobedFuncs := make([]string, 0)

	if len(prefix) == 0 {
		return unprobedFuncs
	}

	// TODO current we use sequential search on the key set, maybe can use trie to speed up
	if prefix[len(prefix)-1] == '$' {
		funcSingature := prefix[:len(prefix)-1]
		for fName, probeRef := range i.userProbes {
			if fName == funcSingature {
				unprobedFuncs = append(unprobedFuncs, fName)
				probeRef.start.Close()
				for _, endProbe := range probeRef.end {
					endProbe.Close()
				}
				delete(i.userProbes, fName)
			}
		}
	} else {
		for fName, probeRef := range i.userProbes {
			if strings.HasPrefix(fName, prefix) {
				unprobedFuncs = append(unprobedFuncs, fName)
				probeRef.start.Close()
				for _, endProbe := range probeRef.end {
					endProbe.Close()
				}
				delete(i.userProbes, fName)
			}
		}
	}

	return unprobedFuncs
}

func getRelatedOffset(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
