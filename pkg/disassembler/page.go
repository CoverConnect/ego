package disassembler

import (
	"reflect"
	"syscall"
	"unsafe"
)

func getPage(p uint64) []byte {
	return (*(*[0xFFFFFF]byte)(unsafe.Pointer(uintptr(p) & ^uintptr(syscall.Getpagesize()-1))))[:syscall.Getpagesize()]
}

// use by segment level
func GetFunctionPage(entry, end uint64) []byte {

	entryAlign := uintptr(entry) & ^uintptr(syscall.Getpagesize()-1)
	endAlign := uintptr(end) & ^uintptr(syscall.Getpagesize()-1)
	entryPage := getPage(entry)

	finalPage := (*(*[0xFFFFF]byte)(unsafe.Pointer(&entryPage[0])))[:int(endAlign-entryAlign)+syscall.Getpagesize()]

	return finalPage
}

// use by instruction level
func MakeSliceFromPointer(p uint64, length int) []byte {
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(p),
		Len:  length,
		Cap:  length,
	}))
}
