package instrument

import (
	"fmt"
	"log"

	"github.com/go-delve/delve/pkg/proc"
)

func init() {

	if err := InitializeTracer("ego", "127.0.0.1:4317"); err != nil {
		log.Fatalf("Failed to initialize tracer: %v", err)
	}

}

func Collect(bi *proc.BinaryInfo) {

	// debug config
	for ctx := range UprobesCtxChan {

		// find back function by pc
		// TODO cache this
		fn := bi.PCToFunc(ctx.FnAddr)
		log.Println("===collected entry===")
		fmt.Println(fn.Name)
		fmt.Printf("Start parent goid: %d,goid: %d\n", ctx.ParentGoroutineId, ctx.GoroutineId)
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

		TraceEntry(fn.Name, ctx)

	}
}
func CollectEnd(bi *proc.BinaryInfo) {
	for ctx := range UretprobesCtxChan {
		log.Println("===collected end===")

		fn := bi.PCToFunc(ctx.FnAddr)
		fmt.Println(fn.Name)
		fmt.Printf("End parent goid: %d,goid: %d\n", ctx.ParentGoroutineId, ctx.GoroutineId)

		// TODO bug in variables
		/*
			variables, err := GetVariablesFromCtx(fn, ctx, bi)
			if err != nil {
				log.Print(err)
				return
			}
			for _, v := range variables {
				v.LoadValue(LoadFullValue)
				PrintV("", *v)
			}
		*/

		TraceDefer(ctx)

	}
}
