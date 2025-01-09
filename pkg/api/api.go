package api

import (
	"log/slog"
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

	slog.Debug("listening", "port", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		slog.Error("Instrument API error:", err)
	}
}
