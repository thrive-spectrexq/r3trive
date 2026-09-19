package api

import (
	"net/http"

	"github.com/thrive-spectrexq/r3trive/internal/api/handlers"
)

// ErrorResponse is the standardized error response envelope.
type ErrorResponse = handlers.ErrorResponse

// WriteError writes a standardized error response envelope.
func WriteError(w http.ResponseWriter, statusCode int, code, message string) {
	handlers.WriteError(w, statusCode, code, message)
}
