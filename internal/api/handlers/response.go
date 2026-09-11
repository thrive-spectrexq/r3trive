package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

// ExecuteActionRequest is the request body for executing a response action.
type ExecuteActionRequest struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
	DryRun bool           `json:"dry_run"`
}

// ExecuteAction triggers a response action via the API.
// Note: This handler accepts the store for consistency but the actual
// response engine integration would be wired in the server setup.
// For now, it validates the request and returns a structured response.
func ExecuteAction(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ExecuteActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Action == "" {
			http.Error(w, "action is required", http.StatusBadRequest)
			return
		}

		slog.Info("response action requested via API",
			"action", req.Action,
			"dry_run", req.DryRun,
			"params", req.Params,
		)

		// Return accepted - actual execution would be handled by the response engine
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "accepted",
			"action":  req.Action,
			"dry_run": req.DryRun,
		})
	}
}
