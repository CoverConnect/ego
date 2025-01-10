package event

import (
	"fmt"

	"github.com/backman-git/delve/pkg/proc"
)

var variableChangeEventBus *VariableChangeEventBus

type VariableChangeEventVariableType int

const (
	VariableTypeArgument VariableChangeEventVariableType = iota
	VariableTypeReturnValue
)

type VariableChangeEvent struct {
	FunctionName string                          `json:"function_name"`
	VariableType VariableChangeEventVariableType `json:"type"`
	Variables    []*Variable                     `json:"variables"`
}

type Variable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VariableChangeEventBus struct {
	listeners []chan *VariableChangeEvent
}

func init() {
	variableChangeEventBus = newVariableChangeEventBus()
}

func GetVariableChangeEventBus() *VariableChangeEventBus {
	return variableChangeEventBus
}

func newVariableChangeEventBus() *VariableChangeEventBus {
	return &VariableChangeEventBus{
		listeners: make([]chan *VariableChangeEvent, 0),
	}
}

func NewVariableChangeEvent(functionName string, variableType VariableChangeEventVariableType, variables []*proc.Variable) *VariableChangeEvent {
	var event = &VariableChangeEvent{}
	event.FunctionName = functionName
	event.VariableType = variableType
	event.Variables = make([]*Variable, 0)

	for _, pvar := range variables {
		var variable = &Variable{}
		variable.Name = pvar.Name
		variable.Value = pvar.Value.String()
		event.Variables = append(event.Variables, variable)
	}

	return event
}

func (eb *VariableChangeEventBus) RegisterListener(listener chan *VariableChangeEvent) {
	eb.listeners = append(eb.listeners, listener)
}

func (eb *VariableChangeEventBus) EmitEvent(event *VariableChangeEvent) {
	for _, listener := range eb.listeners {
		listener <- event
	}
}

func (eb *VariableChangeEventBus) UnregisterListener(listener chan *VariableChangeEvent) {
	for i, l := range eb.listeners {
		if fmt.Sprintf("%p", l) == fmt.Sprintf("%p", listener) { // Compare the memory address of functions
			// Remove the listener
			eb.listeners = append(eb.listeners[:i], eb.listeners[i+1:]...)
			break
		}
	}
}
