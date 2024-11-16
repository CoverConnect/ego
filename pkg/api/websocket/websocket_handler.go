package websocket

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins, but in production you should handle CORS properly.
	},
}

type MessageHandler func(*websocket.Conn, []byte)

var handlers = map[string]MessageHandler{
	"variable_watcher": variableWatcherHandler,
}

func Handler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading to WebSocket:", err)
		return
	}

	defer conn.Close()

	// Read messages from the WebSocket connection
	for {
		// Read a message
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			continue
		}

		// Example: We assume the first byte/character of the message is the command type
		if messageType == websocket.TextMessage {
			// Parse message and handle based on first character (command)
			command := string(p[0]) // Take the first byte as a command (e.g., 'p' for "ping")
			handler, ok := handlers[command]
			if ok {
				handler(conn, p) // Call the handler
			} else {
				log.Println("Unknown command:", command)
				conn.WriteMessage(websocket.TextMessage, []byte("Unknown command"))
			}
		}
	}
}
