package instrument

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-delve/delve/pkg/proc"
)

func init() {

	if err := InitializeTracer("ego", "127.0.0.1:4318"); err != nil {
		log.Fatalf("Failed to initialize tracer: %v", err)
	}

}

func ReadPerf(event *ebpf.Map, ctxCh chan hookFunctionParameterListT) {
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
		//log.Printf("read a perf event")
		ctxCh <- fnCtx
	}
}

func Collect(bi *proc.BinaryInfo, ctxCh chan hookFunctionParameterListT) {

	// debug config
	for ctx := range ctxCh {

		// find back function by pc
		// TODO cache this
		//log.Println("===collected entry===")
		//fmt.Println(fn.Name)
		//fmt.Printf("Start parent goid: %d,goid: %d\n", ctx.ParentGoroutineId, ctx.GoroutineId)
		/*variables, err := GetVariablesFromCtx(fn, ctx, bi)
		if err != nil {
			log.Print(err)
			return
		}
		for _, v := range variables {
			v.LoadValue(LoadFullValue)
			PrintV("", *v)
		}
		*/

		switch ctx.IsRet {
		case false:
			CollectEntry(bi, ctx)

		case true:
			CollectEnd(bi, ctx)
		}

	}
}

func CollectEntry(bi *proc.BinaryInfo, ctx hookFunctionParameterListT) {
	fn := bi.PCToFunc(ctx.FnAddr)

	fmt.Println("====collect entry start====")
	fmt.Printf("====F:%s ============\n", fn.Name)
	fmt.Printf("Start parent goid: %d,goid: %d\n", ctx.ParentGoroutineId, ctx.GoroutineId)
	variables, err := GetVariablesFromCtx(fn, ctx, bi)
	if err != nil {
		log.Print(err)
		return
	}
	for _, v := range variables {
		v.LoadValue(LoadFullValue)
		PrintV("", *v)
	}

	TraceEntry(fn.Name, ctx, variables)
	fmt.Printf("====F:%s ============\n", fn.Name)
	fmt.Println("====collect entry end====")

}

func CollectEnd(bi *proc.BinaryInfo, ctx hookFunctionParameterListT) {
	fn := bi.PCToFunc(ctx.FnAddr)

	fmt.Println("====collect end start====")
	fmt.Printf("====F:%s ============\n", fn.Name)

	fmt.Printf("Start parent goid: %d,goid: %d\n", ctx.ParentGoroutineId, ctx.GoroutineId)
	variables, err := GetVariablesFromCtx(fn, ctx, bi)
	if err != nil {
		log.Print(err)
		return
	}
	for _, v := range variables {
		v.LoadValue(LoadFullValue)
		PrintV("", *v)
	}
	fmt.Printf("====F:%s ============\n", fn.Name)
	fmt.Println("====collect end end====")
	TraceDefer(ctx, variables)

}
