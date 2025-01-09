package instrument

import (
	"github.com/backman-git/delve/pkg/proc"
)

// func TraceEntry(functionName string, ctx hookFunctionParameterListT) {
// 	println("TraceEntry")
// 	println(functionName)
// 	println(ctx.GoroutineId)

// }

// func TraceDefer(ctx context.Context) {
// }
func TraceEntry(functionName string, ctx hookFunctionParameterListT, variables []*proc.Variable) {
	StartSpan(functionName, int(ctx.GoroutineId), int(ctx.ParentGoroutineId), variables)
}

func TraceDefer(ctx hookFunctionParameterListT, variables []*proc.Variable) {
	StopSpan(int(ctx.GoroutineId), variables)
}
