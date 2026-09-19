package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// ErrorResponse represents a standardized JSON error envelope.
type ErrorResponse struct {
	Error     string    `json:"error"`
	Code      string    `json:"code,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// WriteError formats and writes a standardized error envelope as JSON.
func WriteError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := ErrorResponse{
		Error:     message,
		Code:      code,
		Timestamp: time.Now().UTC(),
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode error response", "error", err)
	}
}
