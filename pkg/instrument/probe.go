package instrument

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"log/slog"

	. "github.com/CoverConnect/ego/pkg/config"
	"github.com/CoverConnect/ego/pkg/dmetric"
	"github.com/CoverConnect/ego/pkg/event"
	"github.com/backman-git/delve/pkg/proc"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func init() {

	if err := InitializeTracer("ego", Config.GetString("ego.otlpendpoint")); err != nil {
		slog.Warn("Failed to initialize tracer:", err)
	}

}

// Read value from perf event
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

		ctxCh <- fnCtx
	}
}

func Collect(bi *proc.BinaryInfo, ctxCh chan hookFunctionParameterListT) {

	for ctx := range ctxCh {
		switch ctx.IsRet {
		case false:
			fName, variables := CollectEntry(bi, ctx)
			if TRACE_FUNC {
				TraceEntry(fName, ctx, variables)
			}
		case true:
			_, variables := CollectEnd(bi, ctx)
			if TRACE_FUNC {
				TraceDefer(ctx, variables)
			}
		}

	}
}

func CollectEntry(bi *proc.BinaryInfo, ctx hookFunctionParameterListT) (string, []*proc.Variable) {
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("Collect Entry Recovered", "error", r)
		}
	}()

	fn := bi.PCToFunc(ctx.FnAddr)
	variables, err := GetVariablesFromCtx(fn, ctx, bi, false)
	if err != nil {
		log.Print(err)
		return fn.Name, []*proc.Variable{}
	}

	if LOG_ARG {
		slog.Debug("collect entry", "func", fn.Name)
		for _, v := range variables {
			v.LoadValue(LoadFullValue)
			PrintV("value", *v)
		}
		// send to ws
		event.GetVariableChangeEventBus().EmitEvent(event.NewVariableChangeEvent(fn.Name, event.VariableTypeArgument, variables))
	}

	if LOG_METRIC {
		slog.Debug("collect metric", "func", fn.Name)
		dmetric.Manager.CountHit(fn.Name)

		/*
			for _, v := range variables {

				switch v.Kind {
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					//TODO need to support float
					intV, err := strconv.Atoi(v.Value.String())
					if err != nil {
						slog.Debug("convert to int failed", "error", err)
						continue
					}
					dmetric.Manager.SetArgumentGauge(fn.Name, v.Name, intV)
				}

			}
		*/
	}

	return fn.Name, variables
}

func CollectEnd(bi *proc.BinaryInfo, ctx hookFunctionParameterListT) (string, []*proc.Variable) {

	defer func() {
		if r := recover(); r != nil {
			slog.Debug("Collect End Recovered", "error", r)
		}
	}()

	fn := bi.PCToFunc(ctx.FnAddr)

	variables, err := GetVariablesFromCtx(fn, ctx, bi, true)
	if err != nil {
		log.Print(err)
		return fn.Name, []*proc.Variable{}
	}

	if LOG_RETURN {
		slog.Debug("collect end", "func", fn.Name)
		for _, v := range variables {
			v.LoadValue(LoadFullValue)
			PrintV("", *v)
		}
		event.GetVariableChangeEventBus().EmitEvent(event.NewVariableChangeEvent(fn.Name, event.VariableTypeReturnValue, variables))

	}

	return fn.Name, variables
}
