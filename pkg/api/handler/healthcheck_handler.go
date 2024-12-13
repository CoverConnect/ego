package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type ProcessInfoResponse struct {
	Name string `json:"name"`
}

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	// get process information
	// TODO can have more information
	infoResp := &ProcessInfoResponse{
		Name: os.Args[0],
	}
	log.Println("health")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(infoResp)

}
