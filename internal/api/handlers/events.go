package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/telemetry"
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
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"}); err != nil {
				slog.Error("failed to encode response", "error", err)
			}
			return
		}

		if events == nil {
			events = []event.Event{}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(events); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
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
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "event not found"}); err != nil {
				slog.Error("failed to encode response", "error", err)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(evt); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// BatchIngestEvents handles POST /api/v1/events/batch
func BatchIngestEvents(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to read request body"})
			return
		}

		var events []event.Event
		// Attempt to unmarshal as []event.Event first
		if err := json.Unmarshal(body, &events); err != nil {
			// If not a raw list, check if it's wrapped in {"events": [...]}
			var wrapped struct {
				Events []event.Event `json:"events"`
			}
			if err2 := json.Unmarshal(body, &wrapped); err2 != nil || len(wrapped.Events) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid events batch payload, expected array or {events: []}"})
				return
			}
			events = wrapped.Events
		}

		if len(events) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "batch cannot be empty"})
			return
		}

		if len(events) > 5000 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "batch size exceeds maximum limit of 5000 events"})
			return
		}

		now := time.Now().UTC()
		for i := range events {
			if events[i].ID == "" {
				events[i].ID = fmt.Sprintf("evt_%s", uuid.New().String())
			}
			if events[i].Timestamp.IsZero() {
				events[i].Timestamp = now
			}
		}

		if err := store.SaveEvents(r.Context(), events); err != nil {
			slog.Error("Failed to store batch events", "count", len(events), "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal storage error"})
			return
		}

		telemetry.RecordEvent(r.Context(), int64(len(events)))

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "success",
			"ingested": len(events),
		})
	}
}
