package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// QueryEvents handles GET /api/v1/events
func QueryEvents(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit == 0 {
			limit = 50
		}
		offset, _ := strconv.Atoi(q.Get("offset"))

		var since, until time.Time
		if s := q.Get("since"); s != "" {
			since, _ = time.Parse(time.RFC3339, s)
		}
		if u := q.Get("until"); u != "" {
			until, _ = time.Parse(time.RFC3339, u)
		}

		query := storage.EventQuery{
			Type:     q.Get("type"),
			Severity: q.Get("severity"),
			HostID:   q.Get("host_id"),
			Since:    since,
			Until:    until,
			Limit:    limit,
			Offset:   offset,
		}

		events, err := store.QueryEvents(r.Context(), query)
		if err != nil {
			slog.Error("Failed to query events", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
			return
		}

		if events == nil {
			events = []event.Event{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}

// GetEvent handles GET /api/v1/events/{id}
func GetEvent(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		evt, err := store.GetEvent(r.Context(), id)
		if err != nil {
			slog.Error("Failed to get event", "id", id, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "event not found"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evt)
	}
}
