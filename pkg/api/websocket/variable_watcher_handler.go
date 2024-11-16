package websocket

import (
	"encoding/json"
	"log"

	"github.com/CoverConnect/ego/pkg/event"
	"github.com/gorilla/websocket"
)

func variableWatcherHandler(conn *websocket.Conn, message []byte) {
	channel := make(chan *event.VariableChangeEvent)
	event.GetVariableChangeEventBus().RegisterListener(channel)
	go onVariableChangeEvent(conn, channel)
}

func onVariableChangeEvent(conn *websocket.Conn, eventChan chan *event.VariableChangeEvent) {
	for event := range eventChan {
		jsonData, err := json.Marshal(event)
		if err != nil {
			log.Println("onVariableChangeEvent#Failed to marshal struct to JSON:", err)
			return
		}
		conn.WriteMessage(websocket.TextMessage, jsonData)
	}
	defer closeVariableWatcherHandler(conn, eventChan)
}

func closeVariableWatcherHandler(conn *websocket.Conn, eventChan chan *event.VariableChangeEvent) {
	event.GetVariableChangeEventBus().UnregisterListener(eventChan)
	conn.Close()
}
