package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

// QueryIOCs returns IOCs matching optional type and value filters.
func QueryIOCs(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		iocType := r.URL.Query().Get("type")
		value := r.URL.Query().Get("value")
		iocs, err := store.QueryIOCs(r.Context(), iocType, value)
		if err != nil {
			slog.Error("failed to query IOCs", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(iocs); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// AddIOC creates a new IOC entry.
func AddIOC(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ioc storage.IOCEntry
		if err := json.NewDecoder(r.Body).Decode(&ioc); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if ioc.ID == "" || ioc.Type == "" || ioc.Value == "" {
			http.Error(w, "id, type, and value are required", http.StatusBadRequest)
			return
		}
		if err := store.SaveIOC(r.Context(), ioc); err != nil {
			slog.Error("failed to save IOC", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(ioc); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}
