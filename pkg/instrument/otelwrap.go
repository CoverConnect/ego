package instrument

import (
	// import statements
	"context"
	"fmt"

	// "time"

	"go.opentelemetry.io/otel"
	// "go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	traceSpan "go.opentelemetry.io/otel/trace"
	// "google.golang.org/grpc"
)

// Assume a global context is defined in this package or another shared package

type GOID int

var GLOBALCTX = context.Background()

var SPANSTK map[int][]traceSpan.Span
var CTXSTK map[int][]context.Context

func init() {
	// Initialize GlobalContext
	// todo sync map
	CTXSTK = make(map[int][]context.Context)
	SPANSTK = make(map[int][]traceSpan.Span)

	// 0 idx means root
	CTXSTK[0] = []context.Context{GLOBALCTX}
}

var tracer = otel.Tracer("otelwrap")

func InitializeTracer(serviceName string, collectorAddress string) error {
	//exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	//client := otlptracegrpc.NewClient(otlptracegrpc.WithInsecure(), otlptracegrpc.WithEndpoint(collectorAddress), otlptracegrpc.WithDialOption(grpc.WithBlock()))
	//exporter, err := otlptrace.New(GlobalContext, client)

	headers := map[string]string{
		"content-type": "application/json",
	}

	exporter, err := otlptrace.New(
		context.Background(),
		otlptracehttp.NewClient(
			otlptracehttp.WithEndpoint(collectorAddress),
			otlptracehttp.WithHeaders(headers),
			otlptracehttp.WithInsecure(),
		),
	)

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

	currentCtxStack, ok := CTXSTK[goid]
	if ok {
		ctx, span := tracer.Start(currentCtxStack[len(currentCtxStack)-1], operationName, traceSpan.WithAttributes(attribute.Int("goid", goid), attribute.Int("parentid", parentid)))
		SPANSTK[goid] = append(SPANSTK[goid], span)
		CTXSTK[goid] = append(CTXSTK[goid], ctx)
	} else {

		// New goroutine
		// TODO How should we represent the go statement on tracing?
		// New Ctx to connect back to parent goroutine
		//CTXSTK[parentid] = []context.Context{GLOBALCTX}
		//currentCtxStack = CTXSTK[parentid]

		ctx, span := tracer.Start(GLOBALCTX, operationName, traceSpan.WithAttributes(attribute.Int("goid", goid), attribute.Int("parentid", parentid)))
		SPANSTK[goid] = []traceSpan.Span{span}
		CTXSTK[goid] = []context.Context{ctx}
	}
	fmt.Println("after operation")
	fmt.Println("=====Starting span======")
	fmt.Printf("goid: %d\n", goid)
	fmt.Printf("pgoid: %d\n", parentid)
	fmt.Printf("ctx stk len: %d \n", len(CTXSTK[goid]))
	fmt.Printf("span stk len: %d\n", len(SPANSTK[goid]))
	fmt.Println("=====Starting span======")

	// fmt.Println(CTXSTK)
	// fmt.Println(CTXSTK[len(CTXSTK) - 1])
	// 	ctx, span := tracer.Start(CTXSTK[len(CTXSTK) - 1], operationName)
	// fmt.Println(ctx)
	// 	SPANSTK = append(SPANSTK, span)
	// 	CTXSTK = append(CTXSTK, ctx)

	//fmt.Println("Executing line 4")
}

func StopSpan(goid int) {

	currentSpanStack, ok := SPANSTK[goid]
	if !ok {
		// tail call may call before entry call
		return
	}

	span := currentSpanStack[len(currentSpanStack)-1]
	span.End()

	SPANSTK[goid] = currentSpanStack[:len(currentSpanStack)-1]
	if len(SPANSTK[goid]) == 0 {
		delete(SPANSTK, goid)
	}

	CTXSTK[goid] = CTXSTK[goid][:len(CTXSTK[goid])-1]
	if len(CTXSTK[goid]) == 0 {
		delete(CTXSTK, goid)
	}

	fmt.Println("====end span===")
	fmt.Printf("goid: %d\n", goid)
	fmt.Printf("ctx stk len: %d \n", len(CTXSTK[goid]))
	fmt.Printf("span stk len: %d\n", len(SPANSTK[goid]))
	fmt.Println("====end span===")

}
