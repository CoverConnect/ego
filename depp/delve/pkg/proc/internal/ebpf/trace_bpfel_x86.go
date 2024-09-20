// Code generated by bpf2go; DO NOT EDIT.
//go:build (386 || amd64) && go1.16
// +build 386 amd64
// +build go1.16

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadTrace returns the embedded CollectionSpec for trace.
func loadTrace() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TraceBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load trace: %w", err)
	}

	return spec, err
}

// loadTraceObjects loads trace and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *traceObjects
//     *tracePrograms
//     *traceMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTraceObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTrace()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// traceSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type traceSpecs struct {
	traceProgramSpecs
	traceMapSpecs
}

// traceSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type traceProgramSpecs struct {
	UprobeDlvTrace *ebpf.ProgramSpec `ebpf:"uprobe__dlv_trace"`
}

// traceMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type traceMapSpecs struct {
	ArgMap *ebpf.MapSpec `ebpf:"arg_map"`
	Events *ebpf.MapSpec `ebpf:"events"`
}

// traceObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTraceObjects or ebpf.CollectionSpec.LoadAndAssign.
type traceObjects struct {
	tracePrograms
	traceMaps
}

func (o *traceObjects) Close() error {
	return _TraceClose(
		&o.tracePrograms,
		&o.traceMaps,
	)
}

// traceMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTraceObjects or ebpf.CollectionSpec.LoadAndAssign.
type traceMaps struct {
	ArgMap *ebpf.Map `ebpf:"arg_map"`
	Events *ebpf.Map `ebpf:"events"`
}

func (m *traceMaps) Close() error {
	return _TraceClose(
		m.ArgMap,
		m.Events,
	)
}

// tracePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTraceObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracePrograms struct {
	UprobeDlvTrace *ebpf.Program `ebpf:"uprobe__dlv_trace"`
}

func (p *tracePrograms) Close() error {
	return _TraceClose(
		p.UprobeDlvTrace,
	)
}

func _TraceClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
var _TraceBytes []byte
