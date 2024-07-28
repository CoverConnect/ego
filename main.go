package main

import (
	"fmt"
	"log"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-delve/delve/pkg/proc"
)

var FnName = "main.target"
var binaryPath = "/home/backman/ego/tracee/tracee"

// function_parameter_t tracks function_parameter_t from function_vals.bpf.h
type function_parameter_t struct {
	kind      uint32
	size      uint32
	offset    int32
	in_reg    bool
	n_pieces  int32
	reg_nums  [6]int32
	daddr     uint64
	val       [0x30]byte
	deref_val [0x30]byte
}

// function_parameter_list_t tracks function_parameter_list_t from function_vals.bpf.h
type function_parameter_list_t struct {
	fn_addr      uint64
	n_parameters uint32
	params       [6]function_parameter_t
}

func main() {

	// load binary
	bi := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
	if err := bi.LoadBinaryInfo(binaryPath, 0, nil); err != nil {
		log.Fatal(err)
	}

	// Get main.target Info
	fns, err := bi.FindFunction(FnName)
	if err != nil {
		log.Fatal(err)
	}

	//use ebpf
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs hookObjects
	if err := loadHookObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// open program
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		log.Fatalf("open exec fail %w", err)
	}

	// uprobe to function
	up, err := ex.Uprobe(FnName, objs.UprobeHook, nil)
	if err != nil {
		log.Fatal("set uprobe error", err)
	}
	defer up.Close()

	log.Printf("=== start ===\n")

	//locate a function variables and send to ebpf maps
	for _, fn := range fns {
		args, err := proc.GetArgumentByFunc(bi, fn)
		if err != nil {
			log.Fatal(err)
		}

		// convert to our type
		// 暫時
		fnParaList := &function_parameter_list_t{n_parameters: uint32(len(args))}
		for idx, a := range args {
			para := function_parameter_t{}

			para.kind = uint32(a.Kind)
			para.size = uint32(a.Size)
			para.offset = int32(a.Offset)

			if a.InReg {
				para.in_reg = true
				para.n_pieces = int32(len(a.Pieces))
				for i := range a.Pieces {
					if i > 5 {
						break
					}
					para.reg_nums[i] = int32(a.Pieces[i])
				}
			}
			fnParaList.params[idx] = para
		}

		if err := objs.ArgMap.Update(unsafe.Pointer(&fn.Entry), unsafe.Pointer(fnParaList), ebpf.UpdateAny); err != nil {
			log.Fatal(err)
		}
		fmt.Println(args)
	}

	for {
		time.Sleep(1 * time.Second)
	}

}
