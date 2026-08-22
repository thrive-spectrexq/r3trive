package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

var startTime = time.Now()

// GetHealth handles GET /api/v1/health
func GetHealth(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := map[string]interface{}{
			"status":  "ok",
			"uptime":  time.Since(startTime).String(),
			"version": "1.0.0",
			"storage": "connected",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(health)
	}
}
