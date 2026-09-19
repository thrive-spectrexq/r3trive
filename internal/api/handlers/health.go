package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

var startTime = time.Now()

// GetHealth handles GET /api/v1/health
func GetHealth(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := "ok"
		storageStatus := "connected"
		code := http.StatusOK

		if store != nil {
			if _, err := store.QueryEvents(r.Context(), storage.EventQuery{Limit: 1}); err != nil {
				status = "degraded"
				storageStatus = "error: " + err.Error()
			}
		} else {
			status = "degraded"
			storageStatus = "disconnected"
		}

		health := map[string]interface{}{
			"status":  status,
			"uptime":  time.Since(startTime).String(),
			"version": "1.0.0",
			"storage": storageStatus,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if err := json.NewEncoder(w).Encode(health); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// GetLive handles GET /api/v1/live (liveness probe).
func GetLive() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "live",
		})
	}
}

// GetReady handles GET /api/v1/ready (readiness probe).
func GetReady(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if store == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "unavailable",
				"error":  "storage store not initialized",
			})
			return
		}

		if _, err := store.QueryEvents(r.Context(), storage.EventQuery{Limit: 1}); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "unavailable",
				"error":  err.Error(),
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ready",
		})
	}
}
