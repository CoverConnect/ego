package instrument

import (
	// "context"
	"fmt"

	"github.com/go-delve/delve/pkg/proc"
)

// func TraceEntry(functionName string, ctx hookFunctionParameterListT) {
// 	println("TraceEntry")
// 	println(functionName)
// 	println(ctx.GoroutineId)

// }

// func TraceDefer(ctx context.Context) {
// }
func TraceEntry(functionName string, ctx hookFunctionParameterListT, variables []*proc.Variable) {

	// stacktrace := callback.CollectStacktrace(regs, g, 10)
	// fmt.Println(stacktrace[0].Function)
	// fmt.Println(stacktrace[1].Function)
	// fmt.Println(stacktrace[2].Function)
	// StartSpan(stacktrace[3].Function)
	// goid := int(*(*int64)(unsafe.Pointer(g + 152)))     // goid is int64
	// parentid := int(*(*int64)(unsafe.Pointer(g + 272))) // goid is int64
	// parentid := 0
	StartSpan(functionName, int(ctx.GoroutineId), int(ctx.ParentGoroutineId), variables)
	// fmt.Println("GoId:        ")
	// fmt.Println(GetGoID(GPtr(g)))
	// var a t
	// fmt.Println(unsafe.Offsetof(a.goid))
	// fmt.Println(getOffset())

	// fmt.Println(stacktrace[3].Function)
	// fmt.Println(stacktrace)

	fmt.Println("collect Trace Entry")
	//TODO put open-tracing related code

}

func TraceDefer(ctx hookFunctionParameterListT, variables []*proc.Variable) {

	//fmt.Println("stopppp GoId:        ")
	//fmt.Println(ctx.GoroutineId)
	// stacktrace := callback.CollectStacktrace(regs, g, 10)
	// goid := int(*(*int64)(unsafe.Pointer(g + 152))) // goid is int64
	StopSpan(int(ctx.GoroutineId), variables)
	// fmt.Println(staktrace)

	// fmt.Println("collect Trace defer")
	//TODO put open-tracing related code
}
