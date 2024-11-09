package instrument

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/CoverConnect/ego/internal"
	"github.com/CoverConnect/ego/pkg/disassembler"
	"github.com/backman-git/delve/pkg/proc"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var in *Instrument

func init() {

	// Init instrument library
	exec, err := os.Executable()
	if err != nil {
		log.Printf("Fail to load exec file. path:%s", exec)
		return
	}

	in = NewInstrument(exec)
	in.Start()

	log.Printf("=== Instrument Ready ===\n")
}

type Instrument struct {
	hookObj         *hookObjects
	bi              *proc.BinaryInfo
	ex              *link.Executable
	uprobes         []link.Link
	uretprobes      []link.Link
	binaryPath      string
	FunctionManager *internal.FunctionManager
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
	go Collect(i.bi, CtxChan)

	return nil
}

func (i Instrument) Stop() {

	for _, uprobe := range i.uprobes {
		uprobe.Close()
	}
	for _, uretprobe := range i.uretprobes {
		uretprobe.Close()
	}

	defer i.hookObj.Close()

}

func (i *Instrument) ProbeFunctionWithPrefix(prefix string) {
	// TODO move to instrument type
	goidOffset, err := getGoIDOffset(i.bi)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}

	parentGoidOffset, err := getParentIDOffset(i.bi)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}

	// heavy depend on the platform
	gOffset, err := i.bi.GStructOffset(nil)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}

	// Probe the function with all signature
	uprobes := make([]link.Link, 0)
	uretprobes := make([]link.Link, 0)
	for _, f := range GetFunctionByPrefix(i.bi, prefix) {

		params, err := GetFunctionParameter(i.bi, f, f.Entry, false)
		if err != nil {
			log.Printf("%+v\n", err)
			return
		}

		if err := sendParamToHook(i.hookObj, f.Entry, params, goidOffset, parentGoidOffset, gOffset, false); err != nil {
			log.Printf("%+v\n", err)
			return
		}

		// uprobe to function (trace)
		up, err := i.ex.Uprobe(f.Name, i.hookObj.UprobeHook, nil)
		if err != nil {
			log.Printf("set uprobe error: %v", err)
			continue
		}
		uprobes = append(uprobes, up)
		log.Printf("uprobes fn: %s", f.Name)

		//uprobe to function end
		// refer from delve

		instructions, err := disassembler.Decode(f.Entry, f.End)
		if err != nil {
			log.Printf("%+v\n", err)
			return
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
				log.Printf("%+v\n", err)
				return
			}

			if err := sendParamToHook(i.hookObj, addr, retParams, goidOffset, parentGoidOffset, gOffset, true); err != nil {
				log.Printf("%+v\n", err)
				return
			}

			off := getRelatedOffset(f.Entry, addr)
			log.Printf("set uretprobe: %x, off: %x\n", addr, off)
			end, err := i.ex.Uprobe(f.Name, i.hookObj.UprobeHook, &link.UprobeOptions{Offset: off})
			if err != nil {
				return
			}
			uretprobes = append(uretprobes, end)
			log.Printf("uretprobes fn: %s", f.Name)

		}

	}
	i.uprobes = uprobes
	i.uretprobes = uretprobes
}

func (i *Instrument) UnProbeFunctionWithPrefix(prefix string) {

	// TODO
}

func getRelatedOffset(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
