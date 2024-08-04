package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-delve/delve/pkg/proc"
)

var FnName = "main.target"
var binaryPath = "/home/backman/ego/tracee/tracee"

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

		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
			return
		}

		//log.Fatalf("load program %w", err)

	}
	defer objs.Close()

	// open program
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		log.Fatalf("open exec fail %w", err)
	}

	log.Printf("=== start ===\n")

	// Get Function Dwarf Info
	for _, fn := range fns {
		_, err := proc.GetArgumentByFunc(bi, fn)
		if err != nil {
			log.Fatal(err)
		}

		// send the tracing address
		/*
			err = objs.ContextMap.Update(fn.Entry,)
			if err != nil {
				return err
			}
		*/
	}

	// uprobe to function (trace)
	up, err := ex.Uprobe(FnName, objs.UprobeHook, nil)
	if err != nil {
		log.Fatal("set uprobe error", err)
	}
	defer up.Close()

	rd, err := ringbuf.NewReader(objs.hookMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	var fnCtx hookFunctionContextT
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
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &fnCtx); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		PrintCtx("hit event: ", fnCtx)

		// retrieve variable information

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

}
