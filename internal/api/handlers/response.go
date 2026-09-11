package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/thrive-spectrexq/r3trive/internal/response"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

// ActionExecutor executes a containment or remediation response action.
type ActionExecutor interface {
	Execute(ctx context.Context, action response.ActionType, params map[string]any) (response.ActionResult, error)
}

// ExecuteActionRequest is the request body for executing a response action.
type ExecuteActionRequest struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
	DryRun bool           `json:"dry_run"`
}

// ExecuteAction triggers a response action via the API.
// If executor is provided, the action is executed and the result returned.
// Otherwise, the action is validated and an accepted status is returned.
func ExecuteAction(store storage.Store, executor ActionExecutor) http.HandlerFunc {
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

		if executor != nil {
			res, err := executor.Execute(r.Context(), response.ActionType(req.Action), req.Params)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":  err.Error(),
					"action": req.Action,
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"status": "executed",
				"action": req.Action,
				"result": res,
			}); err != nil {
				slog.Error("failed to encode response", "error", err)
			}
			return
		}

		// Return accepted - placeholder when no executor is wired
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"status":  "accepted",
			"action":  req.Action,
			"dry_run": req.DryRun,
		}); err != nil {
			slog.Error("failed to encode response", "error", err)
		}
	}
}
