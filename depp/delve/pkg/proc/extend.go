package proc

import (
	"debug/dwarf"
	"log"
	"reflect"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/reader"
)

type Parameter struct {
	Name   string
	Offset int64
	Size   int64
	Kind   reflect.Kind
	Pieces []int
	InReg  bool
	Ret    bool
}

func (bi *BinaryInfo) FindType(name string) (godwarf.Type, error) {
	return bi.findType(name)
}

func (fn *Function) GetDwarfTree() (*godwarf.Tree, error) {
	return fn.cu.image.getDwarfTree(fn.offset)
}

func (fn *Function) GetImage() *Image {
	return fn.cu.image
}

func (v *Variable) LoadValue(cfg LoadConfig) {
	v.loadValueInternal(0, cfg)
}

func ReadVarEntry(entry *godwarf.Tree, image *Image) (name string, typ godwarf.Type, err error) {

	return readVarEntry(entry, image)
}

func ConvertEntrytoVariable(entry reader.Variable, addr uint64, image *Image, bi *BinaryInfo, regs *op.DwarfRegisters) (*Variable, error) {
	var mem MemoryReadWriter = &ProcMemory{}
	// TODO Cache this part
	name, dt, err := ReadVarEntry(entry.Tree, image)
	if err != nil {
		return nil, err
	}
	_, pieces, _, err := bi.Location(entry, dwarf.AttrLocation, addr, *regs, nil)
	if err != nil {
		log.Printf("%w", err)
		return nil, err
	}

	if err != nil {
		log.Printf("Failed to locate :%v\n", err)
	}
	if pieces != nil {
		addr = fakeAddressUnresolv
		cmem, _ := CreateCompositeMemory(mem, bi.Arch, *regs, pieces, dt.Common().ByteSize)
		if cmem != nil {
			mem = cmem
		}
	}

	//TODO check this addr implement
	addr = fakeAddressUnresolv
	v := newVariable(name, addr, dt, bi, mem)

	return v, nil
}
