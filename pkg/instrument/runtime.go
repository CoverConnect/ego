package instrument

import (
	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/proc"
)

func getGoIDOffset(bi *proc.BinaryInfo) (int64, error) {

	//Get Types ? no need close?
	rdr := bi.Images[0].DwarfReader()
	rdr.SeekToTypeNamed("runtime.g")

	typ, err := bi.FindType("runtime.g")
	if err != nil {
		return 0, err
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
	return (goidOffset), nil
}

func getParentIDOffset(bi *proc.BinaryInfo) (int64, error) {
	//Get Types ? no need close?
	rdr := bi.Images[0].DwarfReader()
	rdr.SeekToTypeNamed("runtime.g")

	typ, err := bi.FindType("runtime.g")
	if err != nil {
		return 0, err
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
	return (parentGoidOffset), nil
}
