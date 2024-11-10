package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/CoverConnect/ego/pkg/instrument"
)

type Response struct {
	Message string `json:"message"`
}

func TraceHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getHandler(w, r)
	case http.MethodDelete:
		deleteHandler(r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	patternListStr := r.URL.Query().Get("pattern")
	patternList := strings.Split(patternListStr, ",")

	for _, p := range patternList {
		Trace(p)
	}

	w.Header().Set("Content-Type", "application/json")
	response := Response{Message: "ok, " + patternListStr + "!"}
	json.NewEncoder(w).Encode(response)
}

func deleteHandler(r *http.Request) {
	patternListStr := r.URL.Query().Get("pattern")
	patternList := strings.Split(patternListStr, ",")

	for _, p := range patternList {
		UnTrace(p)
	}
}

/*
* sig - signature
* function name
 */
func Trace(sig string) {
	instrument.GetInstrument().ProbeFunctionWithPrefix(sig)
	instrument.GetInstrument().FunctionManager.Register(sig)
}

func UnTrace(sig string) {
	instrument.GetInstrument().UnProbeFunctionWithPrefix(sig)
	instrument.GetInstrument().FunctionManager.UnregisterByName(sig)
}
