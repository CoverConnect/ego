package api

import (
	"log/slog"
	"net/http"

	"github.com/CoverConnect/ego/pkg/api/handler"
	"github.com/CoverConnect/ego/pkg/api/websocket"
	. "github.com/CoverConnect/ego/pkg/config"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Serve() {
	http.HandleFunc("/health", handler.HealthCheckHandler)
	http.HandleFunc("/trace", handler.TraceHandler)
	http.HandleFunc("/functions", handler.GetFunctionHandler)
	http.HandleFunc("/ws", websocket.Handler)
	//metrics
	http.Handle("/metrics", promhttp.Handler())

	port := Config.GetString("ego.port")
	slog.Debug("listening", "port", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		slog.Error("Instrument API error:", err)
	}
}
