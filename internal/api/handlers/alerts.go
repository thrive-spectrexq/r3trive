package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ListAlerts handles GET /api/v1/alerts
func ListAlerts(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 100
		if raw := q.Get("limit"); raw != "" {
			var err error
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 1000 {
				WriteError(w, http.StatusBadRequest, "invalid_limit", "limit must be an integer between 1 and 1000")
				return
			}
		}
		offset := 0
		if raw := q.Get("offset"); raw != "" {
			var err error
			offset, err = strconv.Atoi(raw)
			if err != nil || offset < 0 {
				WriteError(w, http.StatusBadRequest, "invalid_offset", "offset must be a non-negative integer")
				return
			}
		}
		var acknowledged *bool
		if raw := q.Get("acknowledged"); raw != "" {
			value, err := strconv.ParseBool(raw)
			if err != nil {
				WriteError(w, http.StatusBadRequest, "invalid_acknowledged", "acknowledged must be true or false")
				return
			}
			acknowledged = &value
		}
		alerts, err := store.QueryAlerts(r.Context(), storage.AlertQuery{
			Severity: q.Get("severity"), IncidentID: q.Get("incident_id"),
			Acknowledged: acknowledged, Limit: limit, Offset: offset,
		})
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "query_failed", "failed to query alerts")
			return
		}
		if alerts == nil {
			alerts = []event.Alert{}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(alerts); err != nil {
			return
		}
	}
}

// AcknowledgeAlert handles PUT /api/v1/alerts/{id}/acknowledge
func AcknowledgeAlert(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		if err := store.AcknowledgeAlert(r.Context(), id); err != nil {
			WriteError(w, http.StatusNotFound, "alert_not_found", "alert not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged", "id": id})
	}
}
