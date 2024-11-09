package handler

import (
	"encoding/json"
	"net/http"

	"github.com/CoverConnect/ego/internal"
	"github.com/CoverConnect/ego/pkg/instrument"
)

type GetFunctionResponse struct {
	Functions []*Function `json:"functions"`
}

type Function struct {
	Name string `json:"name"`
}

func GetFunctionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	functions := instrument.GetInstrument().FunctionManager.GetAll()
	resp := buildGetFunctionResponse(functions)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

}

func buildGetFunctionResponse(functions []*internal.Function) *GetFunctionResponse {
	funcs := make([]*Function, 0)
	for _, f := range functions {
		funcs = append(funcs, &Function{Name: f.Name})
	}
	return &GetFunctionResponse{Functions: funcs}
}
