package playbook

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/response"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ActionExecutor defines the interface for running response actions.
type ActionExecutor interface {
	Execute(ctx context.Context, action response.ActionType, params map[string]any) (response.ActionResult, error)
}

// Engine manages loading, matching, and executing automated response playbooks.
type Engine struct {
	mu        sync.RWMutex
	playbooks map[string]*Playbook
	dryRun    bool
}

// NewEngine creates a new playbook engine.
func NewEngine(dryRun bool) *Engine {
	return &Engine{
		playbooks: make(map[string]*Playbook),
		dryRun:    dryRun,
	}
}

// Register adds a playbook to the engine.
func (e *Engine) Register(pb *Playbook) error {
	if pb == nil {
		return fmt.Errorf("cannot register nil playbook")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := pb.Validate(); err != nil {
		return err
	}

	e.playbooks[pb.ID] = pb
	slog.Info("registered playbook", "id", pb.ID, "name", pb.Name)
	return nil
}

// LoadDir scans a directory for YAML playbook files and registers them.
func (e *Engine) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read playbook directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext == ".yaml" || ext == ".yml" {
			filePath := filepath.Join(dir, entry.Name())
			pb, err := LoadFromFile(filePath)
			if err != nil {
				slog.Error("failed to load playbook file", "file", filePath, "error", err)
				continue
			}
			if err := e.Register(pb); err != nil {
				slog.Error("failed to register playbook file", "file", filePath, "error", err)
			}
		}
	}

	return nil
}

// ListPlaybooks returns all registered playbooks.
func (e *Engine) ListPlaybooks() []*Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var list []*Playbook
	for _, pb := range e.playbooks {
		list = append(list, pb)
	}
	return list
}

// EvaluateAndExecute finds matching playbooks for an incident and executes them sequentially.
func (e *Engine) EvaluateAndExecute(ctx context.Context, incident event.Incident, executor ActionExecutor) ([]*ExecutionResult, error) {
	e.mu.RLock()
	var matching []*Playbook
	for _, pb := range e.playbooks {
		if pb.Matches(incident) {
			matching = append(matching, pb)
		}
	}
	e.mu.RUnlock()

	if len(matching) == 0 {
		slog.Debug("no playbooks matched incident", "incident_id", incident.ID)
		return nil, nil
	}

	var results []*ExecutionResult
	for _, pb := range matching {
		slog.Info("executing playbook for incident", "playbook_id", pb.ID, "incident_id", incident.ID)
		res, err := e.ExecutePlaybook(ctx, pb, incident, executor)
		if err != nil {
			slog.Error("error running playbook", "playbook_id", pb.ID, "error", err)
		}
		if res != nil {
			results = append(results, res)
		}
	}

	return results, nil
}

// ExecutePlaybook runs a single playbook against an incident.
func (e *Engine) ExecutePlaybook(ctx context.Context, pb *Playbook, incident event.Incident, executor ActionExecutor) (*ExecutionResult, error) {
	startTime := time.Now().UTC()
	execResult := &ExecutionResult{
		PlaybookID:   pb.ID,
		PlaybookName: pb.Name,
		IncidentID:   incident.ID,
		StartTime:    startTime,
		Success:      true,
		StepResults:  make([]StepResult, 0, len(pb.Steps)),
		RollbackPlan: make([]string, 0),
	}

	for _, step := range pb.Steps {
		// Evaluate dynamic parameters
		params := EvaluateParams(step.Params, incident)

		slog.Info("executing playbook step",
			"playbook_id", pb.ID,
			"step_name", step.Name,
			"action", step.Action,
			"params", params,
		)

		res, err := executor.Execute(ctx, step.Action, params)

		stepRes := StepResult{
			StepName:  step.Name,
			Action:    step.Action,
			Success:   res.Success && err == nil,
			Message:   res.Message,
			Timestamp: time.Now().UTC(),
		}

		if err != nil {
			stepRes.Error = err.Error()
		}

		execResult.StepResults = append(execResult.StepResults, stepRes)

		// Record rollback step if action is reversible
		if res.Reversible && res.Success {
			execResult.RollbackPlan = append(execResult.RollbackPlan, fmt.Sprintf("undo %s: %s", step.Action, res.Message))
		}

		// Handle step failure logic
		if !stepRes.Success {
			execResult.Success = false
			strategy := step.OnFailure
			if strategy == "" {
				strategy = OnFailureAbort
			}

			slog.Warn("playbook step failed",
				"playbook_id", pb.ID,
				"step_name", step.Name,
				"on_failure", strategy,
				"error", stepRes.Error,
			)

			switch strategy {
			case OnFailureContinue:
				continue
			case OnFailureAlertAdmin:
				slog.Error("ALERT ADMIN: Playbook step failed",
					"playbook_id", pb.ID,
					"step_name", step.Name,
					"incident_id", incident.ID,
				)
				continue
			case OnFailureAbort:
				slog.Error("aborting playbook execution due to step failure",
					"playbook_id", pb.ID,
					"step_name", step.Name,
				)
				execResult.EndTime = time.Now().UTC()
				return execResult, fmt.Errorf("playbook %s aborted on step '%s': %s", pb.ID, step.Name, stepRes.Error)
			}
		}
	}

	execResult.EndTime = time.Now().UTC()
	return execResult, nil
}
