package instrument

import (
	// import statements
	"context"
	"fmt"

	// "time"

	"go.opentelemetry.io/otel"
	// "go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/attribute"
	// "go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	// "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	traceSpen "go.opentelemetry.io/otel/trace"
	// "google.golang.org/grpc"
)

// Assume a global context is defined in this package or another shared package
var GlobalContext context.Context
var spanStack map[int] []traceSpen.Span
var ctxStack map[int][]context.Context
// var spanStack []traceSpen.Span
// var ctxStack []context.Context

func init() {
	// Initialize GlobalContext
	GlobalContext = context.Background()
	ctxStack = make(map[int][]context.Context)
	spanStack = make(map[int][]traceSpen.Span)
	ctxStack[0] = []context.Context{GlobalContext}
	// ctxStack = append(ctxStack, GlobalContext)
}

func InitializeTracer(serviceName string, collectorAddress string) error {
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	// client := otlptracegrpc.NewClient(otlptracegrpc.WithInsecure(), otlptracegrpc.WithEndpoint(collectorAddress), otlptracegrpc.WithDialOption(grpc.WithBlock()))
	// exporter, err := otlptrace.New(GlobalContext, client)
	if err != nil {
		return err
	}
	resource := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(serviceName),
	)
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(resource),
	)
	otel.SetTracerProvider(tp)
	return nil
}

func StartSpan(operationName string, goid int, parentid int) {
	// fmt.Println(goid, parentid)
	fmt.Println("Starting span")
	tracer := otel.Tracer("otelwrap")
	currentCtxStack, ok := ctxStack[goid]
	fmt.Println(goid)
	fmt.Println(parentid)
	fmt.Println(ctxStack)
	fmt.Println(spanStack)
	if ok {
		// In same goroutine
		fmt.Println("ok before start span")
		ctx, span := tracer.Start(currentCtxStack[len(currentCtxStack) - 1], operationName, traceSpen.WithAttributes(attribute.Int("goid", goid), attribute.Int("parentid", parentid)))
		fmt.Println("ok before append span")
		spanStack[goid] = append(spanStack[goid], span)
		fmt.Println("ok before append ctx")
		ctxStack[goid] = append(ctxStack[goid], ctx)
		fmt.Println("ok after append ctx")
	} else {
		// New goroutine
		fmt.Println("ng before get current ctx")
		currentCtxStack, ok = ctxStack[parentid]
		if !ok {
			fmt.Println("use global ctx")
			ctxStack[parentid] = []context.Context{GlobalContext}
			currentCtxStack = ctxStack[parentid]
		}
		fmt.Println("ng before start span")
		ctx, span := tracer.Start(currentCtxStack[0], operationName, traceSpen.WithAttributes(attribute.Int("goid", goid), attribute.Int("parentid", parentid)))
		fmt.Println("ng before append span")
		spanStack[goid] = []traceSpen.Span{span}
		fmt.Println("ng before append ctx")
		ctxStack[goid] = []context.Context{ctx}
		fmt.Println("ng after append ctx")
	}
	fmt.Println("after operation")
	fmt.Println(ctxStack)
	fmt.Println(spanStack)

	// fmt.Println(ctxStack)
	// fmt.Println(ctxStack[len(ctxStack) - 1])
	// 	ctx, span := tracer.Start(ctxStack[len(ctxStack) - 1], operationName)
	// fmt.Println(ctx)
	// 	spanStack = append(spanStack, span)
	// 	ctxStack = append(ctxStack, ctx)



	fmt.Println("Executing line 4")
}

func StopSpan(goid int) {
	fmt.Println("before get current span stack")
	currentSpanStack := spanStack[goid]
	fmt.Println("before get current span")
	span := currentSpanStack[len(currentSpanStack)-1]
	fmt.Println("before remove last element in current span")
	spanStack[goid] = currentSpanStack[:len(currentSpanStack)-1]
	if len(spanStack[goid]) == 0 {
		delete(spanStack, goid)
	}
	fmt.Println("before remove last element in current ctx")
	ctxStack[goid] = ctxStack[goid][:len(ctxStack[goid])-1]
	if len(ctxStack[goid]) == 0 {
		delete(ctxStack, goid)
	}

	// // span := spanStack[len(spanStack)-1]
	// // spanStack = spanStack[:len(spanStack)-1]
	// // ctxStack = ctxStack[:len(ctxStack)-1]

	span.End()
	fmt.Println("end span")
}
