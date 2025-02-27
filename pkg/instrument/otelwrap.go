package instrument

import (
	// import statements
	"context"

	// "time"

	"github.com/backman-git/delve/pkg/proc"
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

func StartSpan(operationName string, goid int, parentid int, variables []*proc.Variable) {

	currentCtxStack, ok := CTXSTK[goid]
	var span traceSpan.Span
	var ctx context.Context
	if ok {
		ctx, span = tracer.Start(currentCtxStack[len(currentCtxStack)-1], operationName, traceSpan.WithAttributes(attribute.Int("goid", goid), attribute.Int("parentid", parentid)))
		SPANSTK[goid] = append(SPANSTK[goid], span)
		CTXSTK[goid] = append(CTXSTK[goid], ctx)
	} else {

		ctx, span = tracer.Start(GLOBALCTX, operationName, traceSpan.WithAttributes(attribute.Int("goid", goid), attribute.Int("parentid", parentid)))
		SPANSTK[goid] = []traceSpan.Span{span}
		CTXSTK[goid] = []context.Context{ctx}
	}

	// Add Variables
	vAttrs := make([]attribute.KeyValue, 0)
	for _, v := range variables {
		vAttr := attribute.String(v.Name, v.Value.ExactString())
		vAttrs = append(vAttrs, vAttr)
	}
	span.AddEvent("variables", traceSpan.WithAttributes(vAttrs...))
}

func StopSpan(goid int, variables []*proc.Variable) {

	currentSpanStack, ok := SPANSTK[goid]
	if !ok {
		// tail call may call before entry call
		return
	}

	span := currentSpanStack[len(currentSpanStack)-1]

	// Add Variables
	vAttrs := make([]attribute.KeyValue, 0)
	for _, v := range variables {
		vAttr := attribute.String(v.Name, v.Value.ExactString())
		vAttrs = append(vAttrs, vAttr)
	}
	span.AddEvent("variables", traceSpan.WithAttributes(vAttrs...))
	span.End()

	SPANSTK[goid] = currentSpanStack[:len(currentSpanStack)-1]
	if len(SPANSTK[goid]) == 0 {
		delete(SPANSTK, goid)
	}

	CTXSTK[goid] = CTXSTK[goid][:len(CTXSTK[goid])-1]
	if len(CTXSTK[goid]) == 0 {
		delete(CTXSTK, goid)
	}

}
