package instrument

import (
	"errors"
	"fmt"
	"log"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-delve/delve/pkg/proc"
)

func init() {

	//use ebpf
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}
}

type Instrument struct {
	hookObj    *hookObjects
	bi         *proc.BinaryInfo
	uprobes    []link.Link
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

	return &Instrument{bi: bi, binaryPath: binaryPath, hookObj: &hookObj}
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

	// open program to probe
	ex, err := link.OpenExecutable(i.binaryPath)
	if err != nil {
		log.Fatalf("open exec fail %w", err)
	}

	uprobes := make([]link.Link, 0)
	for _, f := range GetFunctionByPrefix(i.bi, prefix) {
		params, err := GetFunctionParameter(i.bi, f)
		if err != nil {
			fmt.Printf("%+v\n", err)
			return
		}
		if err := sendParamToHook(i.hookObj, f.Entry, params); err != nil {
			fmt.Printf("%+v\n", err)
			return
		}

		// uprobe to function (trace)
		up, err := ex.Uprobe(f.Name, i.hookObj.UprobeHook, nil)
		if err != nil {
			log.Printf("set uprobe error: %w", err)
			continue
		}
		uprobes = append(uprobes, up)
		log.Printf("probed fn: %s", f.Name)

	}
	i.uprobes = uprobes
}
