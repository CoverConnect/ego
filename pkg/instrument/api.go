package instrument

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const port = "8888"

func Serve() {
	http.HandleFunc("/trace", TraceHandler)
	fmt.Printf("listen on port:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		println("Error starting server:", err)
	}
}

type Response struct {
	Message string `json:"message"`
}

func TraceHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		patternListStr := r.URL.Query().Get("pattern")
		patternList := strings.Split(patternListStr, ",")

		for _, p := range patternList {
			Trace(p)
		}

		w.Header().Set("Content-Type", "application/json")
		response := Response{Message: "ok, " + patternListStr + "!"}
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

}

func Trace(sig string) {
	in.ProbeFunctionWithPrefix(sig)
}

func UnTrace(sig string) {
	// TODO in.UnProbeFunctionWithPrefix(sig)
}
