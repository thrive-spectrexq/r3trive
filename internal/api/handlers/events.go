package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

		limit := 50
		if rawLimit := q.Get("limit"); rawLimit != "" {
			var err error
			limit, err = strconv.Atoi(rawLimit)
			if err != nil {
				WriteError(w, http.StatusBadRequest, "invalid_limit", "limit must be an integer")
				return
			}
		}
		offset := 0
		if rawOffset := q.Get("offset"); rawOffset != "" {
			var err error
			offset, err = strconv.Atoi(rawOffset)
			if err != nil {
				WriteError(w, http.StatusBadRequest, "invalid_offset", "offset must be an integer")
				return
			}
		}
		if limit == 0 {
			limit = 50
		}
		if limit < 1 || limit > 1000 {
			WriteError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 1000")
			return
		}
		if offset < 0 {
			WriteError(w, http.StatusBadRequest, "invalid_offset", "offset must be non-negative")
			return
		}
		cursor := q.Get("cursor")
		if cursor != "" {
			if _, _, err := storage.DecodeEventCursor(cursor); err != nil {
				WriteError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid")
				return
			}
			if offset != 0 {
				WriteError(w, http.StatusBadRequest, "invalid_pagination", "cursor and offset cannot be used together")
				return
			}
		}

		var since, until time.Time
		if s := q.Get("since"); s != "" {
			var err error
			since, err = time.Parse(time.RFC3339, s)
			if err != nil {
				WriteError(w, http.StatusBadRequest, "invalid_since", "since must be an RFC3339 timestamp")
				return
			}
		}
		if u := q.Get("until"); u != "" {
			var err error
			until, err = time.Parse(time.RFC3339, u)
			if err != nil {
				WriteError(w, http.StatusBadRequest, "invalid_until", "until must be an RFC3339 timestamp")
				return
			}
		}

		query := storage.EventQuery{
			Type:     q.Get("type"),
			Severity: q.Get("severity"),
			HostID:   q.Get("host_id"),
			Since:    since,
			Until:    until,
			Limit:    limit,
			Offset:   offset,
			Cursor:   cursor,
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
		if len(events) == limit {
			last := events[len(events)-1]
			nextCursor := storage.EncodeEventCursor(last.Timestamp, last.ID)
			w.Header().Set("X-Next-Cursor", nextCursor)
			w.Header().Set("Link", fmt.Sprintf(`</api/v1/events?limit=%d&cursor=%s>; rel="next"`, limit, url.QueryEscape(nextCursor)))
		}
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
