package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

// ListRules returns all stored rules.
func ListRules(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enabledOnly := r.URL.Query().Get("enabled") == "true"
		rules, err := store.ListRules(r.Context(), enabledOnly)
		if err != nil {
			slog.Error("failed to list rules", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rules); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// CreateRule creates a new correlation rule.
func CreateRule(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule storage.StoredRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if rule.ID == "" || rule.Name == "" {
			http.Error(w, "id and name are required", http.StatusBadRequest)
			return
		}
		if err := store.SaveRule(r.Context(), rule); err != nil {
			slog.Error("failed to save rule", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(rule); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// UpdateRule updates an existing rule.
func UpdateRule(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var rule storage.StoredRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		rule.ID = id
		if err := store.SaveRule(r.Context(), rule); err != nil {
			slog.Error("failed to update rule", "id", id, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rule); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}

// DeleteRule removes a rule by ID.
func DeleteRule(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if err := store.DeleteRule(r.Context(), id); err != nil {
			slog.Error("failed to delete rule", "id", id, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
