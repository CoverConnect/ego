package instrument

import (
	"errors"
	"fmt"
	"log"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-delve/delve/pkg/dwarf/godwarf"
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

	//goid offset
	rdr := i.bi.Images[0].DwarfReader()
	rdr.SeekToTypeNamed("runtime.g")

	typ, err := i.bi.FindType("runtime.g")
	if err != nil {
		log.Println(err)
		return
	}
	var goidOffset int64
	switch t := typ.(type) {
	case *godwarf.StructType:
		for _, field := range t.Field {
			if field.Name == "goid" {
				goidOffset = field.ByteOffset
				break
			}
		}
	}

	var parentGoidOffset int64
	switch t := typ.(type) {
	case *godwarf.StructType:
		for _, field := range t.Field {
			if field.Name == "parentGoid" {
				parentGoidOffset = field.ByteOffset
				break
			}
		}
	}

	// heavy depend on the platform
	gOffset, err := i.bi.GStructOffset(nil)
	if err != nil {
		fmt.Printf("%+v\n", err)
		return
	}

	uprobes := make([]link.Link, 0)
	for _, f := range GetFunctionByPrefix(i.bi, prefix) {
		params, err := GetFunctionParameter(i.bi, f)

		if err != nil {
			fmt.Printf("%+v\n", err)
			return
		}
		if err := sendParamToHook(i.hookObj, f.Entry, params, goidOffset, parentGoidOffset, gOffset); err != nil {
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
