package api

import (
	"fmt"
	"net/http"

	"github.com/CoverConnect/ego/pkg/api/handler"
	"github.com/CoverConnect/ego/pkg/api/websocket"
)

const port = "8888"

func Serve() {
	http.HandleFunc("/health", handler.HealthCheckHandler)
	http.HandleFunc("/trace", handler.TraceHandler)
	http.HandleFunc("/functions", handler.GetFunctionHandler)
	http.HandleFunc("/ws", websocket.Handler)
	fmt.Printf("listen on port:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		println("Error starting server:", err)
	}
}
