package api

import (
	"fmt"
	"net/http"

	"github.com/CoverConnect/ego/pkg/api/handler"
)

const port = "8888"

func init() {
	http.HandleFunc("/trace", handler.TraceHandler)
	http.HandleFunc("/functions", handler.GetFunctionHandler)
	fmt.Printf("listen on port:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		println("Error starting server:", err)
	}
}
