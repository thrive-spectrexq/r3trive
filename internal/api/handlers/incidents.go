package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ListIncidents handles GET /api/v1/incidents
func ListIncidents(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		statusStr := r.URL.Query().Get("status")
		var statuses []event.IncidentStatus
		if statusStr != "" {
			statuses = []event.IncidentStatus{event.IncidentStatus(statusStr)}
		}

		incidents, err := store.QueryIncidents(r.Context(), statuses)
		if err != nil {
			slog.Error("Failed to query incidents", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"}); err != nil {
				slog.Error("failed to encode response", "error", err)
			}
			return
		}

		if incidents == nil {
			incidents = []event.Incident{}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(incidents); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// GetIncident handles GET /api/v1/incidents/{id}
func GetIncident(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		inc, err := store.GetIncident(r.Context(), id)
		if err != nil {
			slog.Error("Failed to get incident", "id", id, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "incident not found"}); err != nil {
				slog.Error("failed to encode response", "error", err)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(inc); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

type updateIncidentRequest struct {
	Status event.IncidentStatus `json:"status"`
}

// UpdateIncidentStatus handles PUT /api/v1/incidents/{id}/status
func UpdateIncidentStatus(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		var req updateIncidentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"}); err != nil {
				slog.Error("failed to encode response", "error", err)
			}
			return
		}

		if err := store.UpdateIncidentStatus(r.Context(), id, req.Status); err != nil {
			slog.Error("Failed to update incident status", "id", id, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"}); err != nil {
				slog.Error("failed to encode response", "error", err)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "updated", "id": id}); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}
