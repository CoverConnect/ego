package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Rookout/GoSDK/pkg/config"
	"github.com/Rookout/GoSDK/pkg/services/collection/registers"
	"github.com/Rookout/GoSDK/pkg/services/collection/variable"
	"github.com/Rookout/GoSDK/pkg/services/instrumentation/binary_info"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var fnName = "main.target"
var binaryPath = "/home/backman/ego/tracee/tracee"

var CtxChan chan hookFunctionContextT = make(chan hookFunctionContextT, 0)

func main() {

	//use ebpf
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// load binary use delve
	/*
		bi := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
		if err := bi.LoadBinaryInfo(binaryPath, 0, nil); err != nil {
			log.Fatal(err)
		}

		// Get main.target Info
		fns, err := bi.FindFunction(fnName)
		if err != nil {
			log.Fatal(err)
		}
	*/

	// use gosdk
	bi := binary_info.NewBinaryInfo()
	exec := binaryPath

	err := bi.LoadBinaryInfo(exec, binary_info.GetEntrypoint(exec), nil)
	if err != nil {
		log.Fatal(err)
		return
	}
	bi.Dwarf = bi.Images[0].Dwarf

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs hookObjects
	if err := loadHookObjects(&objs, nil); err != nil {

		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
			return
		}
		log.Fatalf("load program %v", err)
	}
	defer objs.Close()

	// open program
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		log.Fatalf("open exec fail %w", err)
	}

	// uprobe to function (trace)
	up, err := ex.Uprobe(fnName, objs.UprobeHook, nil)
	if err != nil {
		log.Fatal("set uprobe error: ", err)
	}
	defer up.Close()

	// go collector
	go ReadPerf(objs.hookMaps.Events)
	go Collect(bi)

	log.Printf("=== start ===\n")
	for {
		fmt.Printf(".")
		time.Sleep(1 * time.Second)
	}

}

func ReadPerf(event *ebpf.Map) {
	var fnCtx hookFunctionContextT

	rd, err := ringbuf.NewReader(event)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	for {

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fnCtx); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		CtxChan <- fnCtx

	}
}

func PrintCtx(head string, ctx hookFunctionContextT) {
	fmt.Println(head)
	fmt.Printf("FnAddr %x\n", ctx.FnAddr)

	fmt.Printf("ax: %x ", ctx.Ax)
	fmt.Printf("bx: %x ", ctx.Bx)
	fmt.Printf("cx: %x ", ctx.Cx)
	fmt.Printf("di: %x ", ctx.Dx)

	fmt.Printf("ip: %x ", ctx.Ip)
	fmt.Printf("sp: %x ", ctx.Sp)
	fmt.Printf("bp: %x ", ctx.Bp)
	fmt.Printf("ss: %x ", ctx.Ss)
	fmt.Printf("si: %x ", ctx.Si)
	fmt.Printf("di: %x ", ctx.Di)
	fmt.Printf("cs: %x ", ctx.Cs)

	fmt.Printf("r8: %x ", ctx.R8)
	fmt.Printf("r9: %x ", ctx.R9)
	fmt.Printf("r10: %x ", ctx.R10)
	fmt.Printf("r11: %x ", ctx.R11)
	fmt.Printf("r12: %x ", ctx.R12)
	fmt.Printf("r13: %x ", ctx.R13)
	fmt.Printf("r14: %x ", ctx.R14)
	fmt.Printf("r15: %x ", ctx.R15)

	fmt.Println("")

}

func ConvertCtxToReg(ctx hookFunctionContextT) *registers.OnStackRegisters {
	regs := &registers.OnStackRegisters{}
	regs.RAX = uintptr(ctx.Ax)
	regs.RBX = uintptr(ctx.Bx)
	regs.RBP = uintptr(ctx.Bp)
	regs.RCX = uintptr(ctx.Cx)
	regs.RDX = uintptr(ctx.Dx)
	regs.RDI = uintptr(ctx.Di)

	regs.RIP = uintptr(ctx.Ip)
	regs.RSP = uintptr(ctx.Sp)
	regs.RSI = uintptr(ctx.Si)

	regs.R9 = uintptr(ctx.R9)
	regs.R10 = uintptr(ctx.R10)
	regs.R11 = uintptr(ctx.R11)
	regs.R12 = uintptr(ctx.R12)
	regs.R13 = uintptr(ctx.R13)
	regs.R14 = uintptr(ctx.R14)
	regs.R15 = uintptr(ctx.R15)

	return regs
}

func Collect(bi *binary_info.BinaryInfo) {

	fn, _ := bi.LookupFunc[fnName]

	config := config.ObjectDumpConfig{
		MaxDepth:           0,
		MaxWidth:           100,
		MaxCollectionDepth: 0,
		MaxString:          64 * 1024,
	}

	vCache := variable.NewVariablesCache()

	for ctx := range CtxChan {
		PrintCtx("Collect: ", ctx)
		regs := ConvertCtxToReg(ctx)

		variableLocators, err := variable.GetVariableLocators(regs.PC(), 0, fn, bi)
		if err != nil {
			log.Fatal(err)
			return
		}

		// retrieve variable information
		for _, varLocator := range variableLocators {
			variable := locateAndLoadVariable(regs, varLocator, config, vCache)
			PrintVariable(variable)
		}
		fmt.Println("")
	}
}
func locateAndLoadVariable(regs registers.Registers, varLocator *variable.VariableLocator, objectDumpConfig config.ObjectDumpConfig, vCache *variable.VariablesCache) (v *variable.Variable) {

	v = varLocator.Locate(regs, 0, vCache, objectDumpConfig)
	if name := v.Name; len(name) > 1 && name[0] == '&' {
		v = v.MaybeDereference()
		if v.Addr == 0 && v.Unreadable == nil {
			v.Unreadable = fmt.Errorf("no address for escaped variable")
		}
		v.Name = name[1:]
	}

	if v.ObjectDumpConfig.ShouldTailor {
		v.UpdateObjectDumpConfig(config.TailorObjectDumpConfig(v.Kind, int(v.Len)))
	}

	v.LoadValue()
	return v
}

func PrintVariable(variable *variable.Variable) {
	fmt.Printf("Name: %s, Value: %s\n", variable.Name, variable.Value.ExactString())
}
