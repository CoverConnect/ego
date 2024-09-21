package instrument

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/reader"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
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

func sendParamToHook(obj *hookObjects, key uint64, params []proc.Parameter, goidOffset, parentGoidOffset int64, gOffset uint64) error {

	paraList, ok := createHookFunctionParameterListT(params, goidOffset, parentGoidOffset, gOffset)
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

// TODO in the future we extend this part to be more flexiable to user
var LoadFullValue = proc.LoadConfig{true, 1, 64, 64, -1, 0}

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
		// TODO cache this
		fn := bi.PCToFunc(ctx.FnAddr)
		fmt.Println(fn.Name)
		fmt.Printf("parent goid: %d,goid: %d\n", ctx.ParentGoroutineId, ctx.GoroutineId)
		variables, err := GetVariablesFromCtx(fn, ctx, bi)
		if err != nil {
			log.Print(err)
			return
		}
		for _, v := range variables {
			v.LoadValue(LoadFullValue)
			PrintV("", *v)
		}

	}
}

func GetVariablesFromCtx(fn *proc.Function, ctx hookFunctionParameterListT, bi *proc.BinaryInfo) ([]*proc.Variable, error) {
	regs := GetRegisterFromCtx(ctx)

	dwarfTree, err := fn.GetDwarfTree()
	if err != nil {
		return nil, errors.New("can't get dwarf tree from function when get variable from ctx")
	}

	_, l := bi.EntryLineForFunc(fn)
	variablesFlags := reader.VariablesOnlyVisible
	image := fn.GetImage()

	varEntries := reader.Variables(dwarfTree, fn.Entry, l, variablesFlags)

	variables := make([]*proc.Variable, 0)
	for _, entry := range varEntries {
		//param := ctx.Params[idx]
		v, err := proc.ConvertEntrytoVariable(entry, fn.Entry, image, bi, regs /*, param.Daddr, param.Val*/)
		if err != nil {

			continue
		}
		variables = append(variables, v)
	}

	return variables, nil
}

func PrintV(ident string, v proc.Variable) {
	ident += "\t"
	fmt.Printf(ident+"Name %s\n", v.Name)
	if v.Value != nil {
		fmt.Printf(ident+"type: %s, value: %s\n", v.RealType, v.Value.ExactString())
	}
	if v.Children != nil {
		for _, v := range v.Children {
			PrintV(ident, v)
		}
	}

}

func createHookFunctionParameterListT(args []proc.Parameter, goidOffset, parentGoid int64, gOffset uint64) (*hookFunctionParameterListT, bool) {
	// due to the hookFunctionParameterListT define para[6]
	if len(args) > 6 {
		return nil, false
	}

	paraList := &hookFunctionParameterListT{}
	paraList.N_parameters = uint32(len(args))
	paraList.GoidOffset = uint32(goidOffset)
	paraList.ParentGoidOffset = uint32(parentGoid)
	paraList.G_addrOffset = int64(gOffset)
	for idx, arg := range args {

		for idy := 0; idy < len(arg.Name); idy++ {
			paraList.Params[idx].Name[idy] = int8(arg.Name[idy])
		}

		paraList.Params[idx].Offset = int32(arg.Offset)
		//paraList.Params[idx].Kind = uint32(arg.Kind)
		paraList.Params[idx].Size = uint32(arg.Size)
		paraList.Params[idx].InReg = arg.InReg

		/*
			if arg.InReg {
				paraList.Params[idx].N_pieces = int32(len(arg.Pieces))
				for idx, v := range arg.Pieces {
					paraList.Params[idx].RegNums[idx] = int32(v)
				}
			}
		*/
	}
	return paraList, true
}

func GetFunctionParameter(bi *proc.BinaryInfo, f *proc.Function) ([]proc.Parameter, error) {

	dwarfTree, err := f.GetDwarfTree()
	if err != nil {
		return nil, err
	}

	_, l := bi.EntryLineForFunc(f)
	variablesFlags := reader.VariablesOnlyVisible
	varEntries := reader.Variables(dwarfTree, f.Entry, l, variablesFlags)

	var args []proc.Parameter
	for _, entry := range varEntries {
		image := f.GetImage()
		name, dt, err := proc.ReadVarEntry(entry.Tree, image)
		if err != nil {
			log.Printf("%w", err)
			continue
		}
		// TODO cache this part
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

		args = append(args, proc.Parameter{
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

func GetRegisterFromCtx(ctx hookFunctionParameterListT) *op.DwarfRegisters {

	dregs := make([]*op.DwarfRegister, regnum.AMD64MaxRegNum()+1)

	dregs[regnum.AMD64_Rdi] = op.DwarfRegisterFromUint64(ctx.Ctx.Di)
	dregs[regnum.AMD64_Rsi] = op.DwarfRegisterFromUint64(ctx.Ctx.Si)
	dregs[regnum.AMD64_Rdx] = op.DwarfRegisterFromUint64(ctx.Ctx.Dx)
	dregs[regnum.AMD64_Rcx] = op.DwarfRegisterFromUint64(ctx.Ctx.Cx)
	dregs[regnum.AMD64_R8] = op.DwarfRegisterFromUint64(ctx.Ctx.R8)
	dregs[regnum.AMD64_R9] = op.DwarfRegisterFromUint64(ctx.Ctx.R9)
	dregs[regnum.AMD64_Rax] = op.DwarfRegisterFromUint64(ctx.Ctx.Ax)
	dregs[regnum.AMD64_Rbx] = op.DwarfRegisterFromUint64(ctx.Ctx.Bx)
	dregs[regnum.AMD64_Rbp] = op.DwarfRegisterFromUint64(ctx.Ctx.Bp)
	dregs[regnum.AMD64_R10] = op.DwarfRegisterFromUint64(ctx.Ctx.R10)
	dregs[regnum.AMD64_R11] = op.DwarfRegisterFromUint64(ctx.Ctx.R11)
	dregs[regnum.AMD64_R12] = op.DwarfRegisterFromUint64(ctx.Ctx.R12)
	dregs[regnum.AMD64_R13] = op.DwarfRegisterFromUint64(ctx.Ctx.R13)
	dregs[regnum.AMD64_R14] = op.DwarfRegisterFromUint64(ctx.Ctx.R14)
	dregs[regnum.AMD64_R15] = op.DwarfRegisterFromUint64(ctx.Ctx.R15)
	/*
		dregs[regnum.AMD64_Fs] = op.DwarfRegisterFromUint64(uint64(mctxt.mc_fs))
		dregs[regnum.AMD64_Gs] = op.DwarfRegisterFromUint64(uint64(mctxt.mc_gs))
		dregs[regnum.AMD64_Es] = op.DwarfRegisterFromUint64(uint64(mctxt.mc_es))
		dregs[regnum.AMD64_Ds] = op.DwarfRegisterFromUint64(uint64(mctxt.mc_ds))
	*/
	dregs[regnum.AMD64_Rip] = op.DwarfRegisterFromUint64(ctx.Ctx.Ip)
	dregs[regnum.AMD64_Cs] = op.DwarfRegisterFromUint64(ctx.Ctx.Cs)
	dregs[regnum.AMD64_Rflags] = op.DwarfRegisterFromUint64(ctx.Ctx.Flags)
	dregs[regnum.AMD64_Rsp] = op.DwarfRegisterFromUint64(ctx.Ctx.Sp)
	dregs[regnum.AMD64_Ss] = op.DwarfRegisterFromUint64(ctx.Ctx.Ss)

	return op.NewDwarfRegisters(0, dregs, binary.LittleEndian, regnum.AMD64_Rip, regnum.AMD64_Rsp, regnum.AMD64_Rbp, 0)
}

func GetParametersFromCtx(ctx hookFunctionParameterListT) []proc.Parameter {

	parameters := make([]proc.Parameter, 0)
	for _, p := range ctx.Params {
		param := proc.Parameter{
			Offset: int64(p.Offset),
			Size:   int64(p.Size),
			//Kind:   reflect.Kind(p.Kind),
			Pieces: make([]int, 6),
		}
		/*
			if p.InReg {
				for idx, v := range p.RegNums {
					param.Pieces[idx] = int(v)
				}
			}
		*/
		name := make([]byte, 0)
		for idx := 0; idx < 10; idx++ {
			name = append(name, byte(p.Name[idx]))
		}
		param.Name = string(name)
		parameters = append(parameters, param)
	}
	return parameters
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
