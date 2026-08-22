package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ListAlerts handles GET /api/v1/alerts
func ListAlerts(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Placeholder since store doesn't have QueryAlerts yet
		alerts := []event.Alert{}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(alerts)
	}
}

// AcknowledgeAlert handles PUT /api/v1/alerts/{id}/acknowledge
func AcknowledgeAlert(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged", "id": id})
	}
}
