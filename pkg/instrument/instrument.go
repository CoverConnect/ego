package instrument

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-delve/delve/pkg/proc"
)

var in *Instrument

func init() {

	//use ebpf
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

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
	hookObj    *hookObjects
	bi         *proc.BinaryInfo
	ex         *link.Executable
	uprobes    []link.Link
	uretprobe   []link.Link
	binaryPath string
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

	return &Instrument{bi: bi, binaryPath: binaryPath, hookObj: &hookObj, ex: ex}
}

func (i Instrument) Start() error {

	// go collector
	go ReadPerf(i.hookObj.hookMaps.Events)
	go Collect(i.bi)

	return nil
}

func (i Instrument) Stop() {

	for _, uprobe := range i.uprobes {
		uprobe.Close()
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
	uretprobe := make([]link.Link, 0)
	for _, f := range GetFunctionByPrefix(i.bi, prefix) {
		params, err := GetFunctionParameter(i.bi, f)

		if err != nil {
			log.Printf("%+v\n", err)
			return
		}
		if err := sendParamToHook(i.hookObj, f.Entry, params, goidOffset, parentGoidOffset, gOffset); err != nil {
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

		uret, err := i.ex.Uretprobe(f.Name, i.hookObj.UretprobeHook, nil)
		if err != nil {
			log.Printf("set uretprobe error: %w", err)
			continue
		}
		uretprobe = append(uretprobe, uret)
		log.Printf("uretprobe fn: %s", f.Name)

	}
	i.uprobes = uprobes
	i.uretprobe = uretprobe
}

func (i *Instrument) UnProbeFunctionWithPrefix(prefix string) {

	// TODO
}
