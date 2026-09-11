package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

// ListHosts returns all registered hosts.
func ListHosts(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hosts, err := store.ListHosts(r.Context())
		if err != nil {
			slog.Error("failed to list hosts", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(hosts); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// GetHost returns a specific host by ID.
func GetHost(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		host, err := store.GetHost(r.Context(), id)
		if err != nil {
			slog.Error("failed to get host", "id", id, "error", err)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(host); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// RegisterHost creates or updates a host record.
func RegisterHost(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var host storage.Host
		if err := json.NewDecoder(r.Body).Decode(&host); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if host.ID == "" || host.Hostname == "" {
			http.Error(w, "id and hostname are required", http.StatusBadRequest)
			return
		}
		if err := store.SaveHost(r.Context(), host); err != nil {
			slog.Error("failed to save host", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(host); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}
