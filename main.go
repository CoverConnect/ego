package main

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/Rookout/GoSDK/pkg/config"
	"github.com/Rookout/GoSDK/pkg/services/collection/registers"
	"github.com/Rookout/GoSDK/pkg/services/collection/variable"
	"github.com/Rookout/GoSDK/pkg/services/instrumentation/binary_info"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/reader"
	"github.com/go-delve/delve/pkg/proc"
)

var binaryPath = "/root/ego/tracee/tracee"

var CtxChan chan hookFunctionParameterListT = make(chan hookFunctionParameterListT, 0)

func main() {

	//use ebpf
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// open program
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		log.Fatalf("open exec fail %w", err)
	}

	//*************** we need to merge two bi into one*************************

	// load binary use delve
	bi := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
	if err := bi.LoadBinaryInfo(binaryPath, 0, nil); err != nil {
		log.Fatal(err)
	}

	// use gosdk
	rbi := binary_info.NewBinaryInfo()
	exec := binaryPath

	err = rbi.LoadBinaryInfo(exec, binary_info.GetEntrypoint(exec), nil)
	if err != nil {
		log.Fatal(err)
		return
	}
	rbi.Dwarf = rbi.Images[0].Dwarf

	//*************** we need to merge two bi into one*************************

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

	for _, f := range GetFunctionByPrefix(bi, "main") {
		// prepare memory address to ebpf if any
		if err := SendArgsCollectInfo(objs, bi, f.Name); err != nil {
			fmt.Printf("%+v\n", err)

			return
		}

		// uprobe to function (trace)
		up, err := ex.Uprobe(f.Name, objs.UprobeHook, nil)
		if err != nil {
			log.Printf("set uprobe error: ", err)
			continue
		}
		defer up.Close()
	}

	// go collector
	go ReadPerf(objs.hookMaps.Events)
	go Collect(bi, rbi)

	log.Printf("=== start ===\n")
	for {
		fmt.Printf(".")
		time.Sleep(1 * time.Second)
	}

}

func GetFunctionByPrefix(bi *proc.BinaryInfo, prefix string) []proc.Function {
	fns := make([]proc.Function, 0)
	for _, f := range bi.Functions {
		if strings.HasPrefix(f.Name, prefix) {
			fns = append(fns, f)
		}

	}

	return fns
}

func SendArgsCollectInfo(obj hookObjects, bi *proc.BinaryInfo, fnName string) error {

	// Get main.target Info
	fns, err := bi.FindFunction(fnName)
	if err != nil {
		log.Fatal(err)
	}

	// prepare variable reader
	fn := fns[0]
	dwarfTree, err := fn.GetDwarfTree()
	if err != nil {
		return err
	}
	_, l := bi.EntryLineForFunc(fn)
	variablesFlags := reader.VariablesOnlyVisible
	varEntries := reader.Variables(dwarfTree, fn.Entry, l, variablesFlags)

	var args []parameter
	for _, entry := range varEntries {
		image := fn.GetImage()
		name, dt, err := proc.ReadVarEntry(entry.Tree, image)
		if err != nil {
			return err
		}

		offset, pieces, _, err := bi.Location(entry, dwarf.AttrLocation, fn.Entry, op.DwarfRegisters{}, nil)
		if err != nil {
			log.Printf("%w", err)
			continue
		}
		paramPieces := make([]int, 0, len(pieces))
		for _, piece := range pieces {
			if piece.Kind == op.RegPiece {
				paramPieces = append(paramPieces, int(piece.Val))
			}
		}
		isret, _ := entry.Val(dwarf.AttrVarParam).(bool)
		offset += int64(bi.Arch.PtrSize())

		args = append(args, parameter{
			Name:   name,
			Offset: offset,
			Size:   dt.Size(),
			Kind:   dt.Common().ReflectKind,
			Pieces: paramPieces,
			InReg:  len(pieces) > 0,
			Ret:    isret,
		})
	}
	paraList, ok := CreateHookFunctionParameterListT(args)
	if !ok {
		log.Printf("Can't CreateHookFunctionParameterListT")
	}
	obj.ContextMap.Update(unsafe.Pointer(&fn.Entry), unsafe.Pointer(paraList), ebpf.UpdateAny)

	return nil
}

type parameter struct {
	Name   string
	Offset int64        // Offset from the stackpointer.
	Size   int64        // Size in bytes.
	Kind   reflect.Kind // Kind of variable.
	Pieces []int        // Pieces of the variables as stored in registers.
	InReg  bool         // True if this param is contained in a register.
	Ret    bool
}

func CreateHookFunctionParameterListT(args []parameter) (*hookFunctionParameterListT, bool) {
	// due to the hookFunctionParameterListT define para[6]
	if len(args) > 6 {
		return nil, false
	}

	paraList := &hookFunctionParameterListT{}
	paraList.N_parameters = uint32(len(args))

	for idx, arg := range args {
		paraList.Params[idx].Offset = int32(arg.Offset)
		paraList.Params[idx].Kind = uint32(arg.Kind)
		paraList.Params[idx].Size = uint32(arg.Size)
		paraList.Params[idx].InReg = arg.InReg
	}
	return paraList, true
}

func ReadPerf(event *ebpf.Map) {
	var fnCtx hookFunctionParameterListT

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

func PrintCtx(head string, ctx hookFunctionParameterListT) {
	fmt.Println(head)
	fmt.Printf("FnAddr %x\n", ctx.FnAddr)

	fmt.Printf("ax: %x ", ctx.Ctx.Ax)
	fmt.Printf("bx: %x ", ctx.Ctx.Bx)
	fmt.Printf("cx: %x ", ctx.Ctx.Cx)
	fmt.Printf("di: %x ", ctx.Ctx.Dx)

	fmt.Printf("ip: %x ", ctx.Ctx.Ip)
	fmt.Printf("sp: %x ", ctx.Ctx.Sp)
	fmt.Printf("bp: %x ", ctx.Ctx.Bp)
	fmt.Printf("ss: %x ", ctx.Ctx.Ss)
	fmt.Printf("si: %x ", ctx.Ctx.Si)
	fmt.Printf("di: %x ", ctx.Ctx.Di)
	fmt.Printf("cs: %x ", ctx.Ctx.Cs)

	fmt.Printf("r8: %x ", ctx.Ctx.R8)
	fmt.Printf("r9: %x ", ctx.Ctx.R9)
	fmt.Printf("r10: %x ", ctx.Ctx.R10)
	fmt.Printf("r11: %x ", ctx.Ctx.R11)
	fmt.Printf("r12: %x ", ctx.Ctx.R12)
	fmt.Printf("r13: %x ", ctx.Ctx.R13)
	fmt.Printf("r14: %x ", ctx.Ctx.R14)
	fmt.Printf("r15: %x ", ctx.Ctx.R15)
	fmt.Println("")

	//print param
	fmt.Println("=========")
	fmt.Println("para")
	fmt.Println("=========")

	for idx := 0; idx < int(ctx.N_parameters); idx++ {
		fmt.Printf("%d. Mem Val: %v\n", idx, ctx.Params[idx].Val)
	}
	fmt.Println("")

}

func ConvertCtxToReg(ctx hookFunctionParameterListT) *registers.OnStackRegisters {
	regs := &registers.OnStackRegisters{}
	regs.RAX = uintptr(ctx.Ctx.Ax)
	regs.RBX = uintptr(ctx.Ctx.Bx)
	regs.RBP = uintptr(ctx.Ctx.Bp)
	regs.RCX = uintptr(ctx.Ctx.Cx)
	regs.RDX = uintptr(ctx.Ctx.Dx)
	regs.RDI = uintptr(ctx.Ctx.Di)

	regs.RIP = uintptr(ctx.Ctx.Ip)
	regs.RSP = uintptr(ctx.Ctx.Sp)
	regs.RSI = uintptr(ctx.Ctx.Si)

	regs.R9 = uintptr(ctx.Ctx.R9)
	regs.R10 = uintptr(ctx.Ctx.R10)
	regs.R11 = uintptr(ctx.Ctx.R11)
	regs.R12 = uintptr(ctx.Ctx.R12)
	regs.R13 = uintptr(ctx.Ctx.R13)
	regs.R14 = uintptr(ctx.Ctx.R14)
	regs.R15 = uintptr(ctx.Ctx.R15)

	return regs
}

func Collect(bi *proc.BinaryInfo, rbi *binary_info.BinaryInfo) {

	// debug config
	/*
		config := config.ObjectDumpConfig{
			MaxDepth:           0,
			MaxWidth:           100,
			MaxCollectionDepth: 0,
			MaxString:          64 * 1024,
		}
		vCache := variable.NewVariablesCache()
	*/
	for ctx := range CtxChan {
		// find back function by pc
		fn := rbi.PCToFunc(ctx.FnAddr)
		fmt.Println(fn.Name)
		/*
			PrintCtx("Collect: ", ctx)
			regs := ConvertCtxToReg(ctx)

			variableLocators, err := variable.GetVariableLocators(regs.PC(), 0, fn, rbi)
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
		*/
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
	if variable.Value != nil {
		fmt.Printf("Name: %s, Value: %s\n", variable.Name, variable.Value.String())
	} else {
		fmt.Printf("Name: %s, Value maybe in stack\n", variable.Name)
	}
}
