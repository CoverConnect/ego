package instrument

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"unsafe"

	"github.com/Rookout/GoSDK/pkg/config"
	"github.com/Rookout/GoSDK/pkg/services/collection/registers"
	"github.com/Rookout/GoSDK/pkg/services/collection/variable"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/reader"
	"github.com/go-delve/delve/pkg/proc"
)

var CtxChan chan hookFunctionParameterListT = make(chan hookFunctionParameterListT, 0)

func GetFunctionByPrefix(bi *proc.BinaryInfo, prefix string) []*proc.Function {
	fns := make([]*proc.Function, 0)
	for _, f := range bi.Functions {
		if strings.HasPrefix(f.Name, prefix) {
			fns = append(fns, &f)
		}

	}

	return fns
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

func GetFunctionParameter(bi *proc.BinaryInfo, f *proc.Function) ([]parameter, error) {

	dwarfTree, err := f.GetDwarfTree()
	if err != nil {
		return nil, err
	}

	_, l := bi.EntryLineForFunc(f)
	variablesFlags := reader.VariablesOnlyVisible
	varEntries := reader.Variables(dwarfTree, f.Entry, l, variablesFlags)

	var args []parameter
	for _, entry := range varEntries {
		image := f.GetImage()
		name, dt, err := proc.ReadVarEntry(entry.Tree, image)
		if err != nil {
			log.Printf("%w", err)
			continue
		}

		offset, pieces, _, err := bi.Location(entry, dwarf.AttrLocation, f.Entry, op.DwarfRegisters{}, nil)
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
	return args, nil
}

func createHookFunctionParameterListT(args []parameter) (*hookFunctionParameterListT, bool) {
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

func sendParamToHook(obj *hookObjects, key uint64, params []parameter) error {

	paraList, ok := createHookFunctionParameterListT(params)
	if !ok {
		return errors.New("Can't CreateHookFunctionParameterListT")

	}
	obj.ContextMap.Update(key, unsafe.Pointer(paraList), ebpf.UpdateAny)

	return nil
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

// TODO in the future we extend this part to be more flexiable to user

func Collect(bi *proc.BinaryInfo) {

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
		//PrintCtx("Collect: ", ctx)
		// find back function by pc
		fn := bi.PCToFunc(ctx.FnAddr)
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
