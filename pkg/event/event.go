package event

import "github.com/gorilla/websocket"

// EventListener is the type of the function that handles events
type EventListener[T any] func(conn *websocket.Conn, event T)

type EventBus[T any] interface {
	Getlisteners() []chan T
	RegisterListener(listener chan T)
	EmitEvent(event T)
	UnregisterListener(listener chan T)
}
