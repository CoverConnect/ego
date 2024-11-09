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

/*
* sig - signature
* function name
 */
func Trace(sig string) {
	instrument.GetInstrument().ProbeFunctionWithPrefix(sig)
	instrument.GetInstrument().FunctionManager.Register(sig)
}

func UnTrace(sig string) {
	// TODO in.UnProbeFunctionWithPrefix(sig)
}
