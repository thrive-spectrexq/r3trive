package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// APIKeyAuth validates the X-API-Key header against the configured API key.
// If no API key is configured, it skips authentication (for local dev).
func APIKeyAuth(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			key := r.Header.Get("X-API-Key")
			if key != apiKey {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized: invalid or missing API key"}); err != nil {
					slog.Error("failed to encode response", "error", err)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
