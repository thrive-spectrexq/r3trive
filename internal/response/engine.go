// Package response implements the Response Core, which executes containment
// and remediation actions in response to detected threats.
//
// See SYSTEM_ARCHITECTURE.md §4.5 for full specification.
package response

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ActionType represents a response action category.
type ActionType string

// Supported response action types.
const (
	ActionKillProcess    ActionType = "kill_process"
	ActionBlockIP        ActionType = "block_ip"
	ActionQuarantine     ActionType = "quarantine_file"
	ActionDisableAccount ActionType = "disable_account"
	ActionIsolateHost    ActionType = "isolate_host"
	ActionKillConnection ActionType = "kill_connection"
	ActionDisableService ActionType = "disable_service"
)

// ActionResult holds the outcome of executing a response action.
type ActionResult struct {
	Action     ActionType `json:"action"`
	Success    bool       `json:"success"`
	Message    string     `json:"message"`
	Timestamp  time.Time  `json:"timestamp"`
	Reversible bool       `json:"reversible"`
}

// Engine executes response actions and manages playbooks.
type Engine struct {
	dryRun  bool
	actions map[ActionType]ActionHandler
}

// ActionHandler is the function signature for action implementations.
type ActionHandler func(ctx context.Context, params map[string]any) (ActionResult, error)

// New creates a new response engine.
func New(dryRun bool) *Engine {
	e := &Engine{
		dryRun:  dryRun,
		actions: make(map[ActionType]ActionHandler),
	}

	// Register built-in actions (platform-specific implementations added later)
	e.actions[ActionKillProcess] = e.killProcess
	e.actions[ActionBlockIP] = e.blockIP
	e.actions[ActionQuarantine] = e.quarantineFile
	e.actions[ActionIsolateHost] = e.isolateHost

	return e
}

// Execute runs a response action with the given parameters.
func (e *Engine) Execute(ctx context.Context, action ActionType, params map[string]any) (ActionResult, error) {
	handler, ok := e.actions[action]
	if !ok {
		return ActionResult{}, fmt.Errorf("unknown action type: %s", action)
	}

	if e.dryRun {
		slog.Info("dry-run: would execute action", "action", action, "params", params)
		return ActionResult{
			Action:    action,
			Success:   true,
			Message:   fmt.Sprintf("[DRY-RUN] Would execute %s", action),
			Timestamp: time.Now().UTC(),
		}, nil
	}

	result, err := handler(ctx, params)
	if err != nil {
		slog.Error("action failed", "action", action, "error", err)
		return result, err
	}

	slog.Info("action executed", "action", action, "success", result.Success)
	return result, nil
}

// RespondToIncident evaluates an incident and executes appropriate responses.
func (e *Engine) RespondToIncident(ctx context.Context, incident event.Incident, threshold int) ([]ActionResult, error) {
	if incident.RiskScore < threshold {
		slog.Debug("incident below threshold, skipping response",
			"incident_id", incident.ID,
			"risk_score", incident.RiskScore,
			"threshold", threshold,
		)
		return nil, nil
	}

	slog.Info("responding to incident",
		"incident_id", incident.ID,
		"risk_score", incident.RiskScore,
	)

	var results []ActionResult

	// 1. Check if we should isolate the host (e.g. Critical severity)
	if incident.Severity == event.SeverityCritical {
		res, err := e.Execute(ctx, ActionIsolateHost, nil)
		if err == nil {
			results = append(results, res)
		}
	}

	// 2. Iterate through alerts to find actionable items
	for _, alert := range incident.Alerts {
		if alert.Event.Data.Process != nil {
			// Kill malicious processes
			res, err := e.Execute(ctx, ActionKillProcess, map[string]any{"pid": alert.Event.Data.Process.PID})
			if err == nil {
				results = append(results, res)
			}
		}

		if alert.Event.Data.Network != nil {
			// Block malicious IPs (Destination IP)
			dstIP := alert.Event.Data.Network.DstIP
			if dstIP != "" && dstIP != "127.0.0.1" && dstIP != "0.0.0.0" {
				res, err := e.Execute(ctx, ActionBlockIP, map[string]any{"ip": dstIP})
				if err == nil {
					results = append(results, res)
				}
			}
		}

		if alert.Event.Data.File != nil {
			// Quarantine malicious files
			res, err := e.Execute(ctx, ActionQuarantine, map[string]any{"path": alert.Event.Data.File.Path})
			if err == nil {
				results = append(results, res)
			}
		}
	}

	// 3. Process artifact paths from the incident itself
	for _, path := range incident.ArtifactPaths {
		res, err := e.Execute(ctx, ActionQuarantine, map[string]any{"path": path})
		if err == nil {
			results = append(results, res)
		}
	}

	return results, nil
}

func (e *Engine) killProcess(ctx context.Context, params map[string]any) (ActionResult, error) {
	pidVal, ok := params["pid"]
	if !ok {
		return ActionResult{}, fmt.Errorf("missing pid parameter")
	}

	// Convert pid to int (might be float64 from JSON or int from struct)
	var pid int
	switch v := pidVal.(type) {
	case int:
		pid = v
	case float64:
		pid = int(v)
	case int64:
		pid = int(v)
	default:
		return ActionResult{}, fmt.Errorf("invalid pid type: %T", pidVal)
	}

	err := sysKillProcess(ctx, pid)
	success := err == nil
	msg := fmt.Sprintf("Killed process %d", pid)
	if !success {
		msg = fmt.Sprintf("Failed to kill process %d: %v", pid, err)
	}

	return ActionResult{
		Action:     ActionKillProcess,
		Success:    success,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: false,
	}, nil
}

func (e *Engine) blockIP(ctx context.Context, params map[string]any) (ActionResult, error) {
	ipVal, ok := params["ip"]
	if !ok {
		return ActionResult{}, fmt.Errorf("missing ip parameter")
	}
	ip, ok := ipVal.(string)
	if !ok {
		return ActionResult{}, fmt.Errorf("invalid ip type: %T", ipVal)
	}

	err := sysBlockIP(ctx, ip)
	success := err == nil
	msg := fmt.Sprintf("Blocked IP %s", ip)
	if !success {
		msg = fmt.Sprintf("Failed to block IP %s: %v", ip, err)
	}

	return ActionResult{
		Action:     ActionBlockIP,
		Success:    success,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: true,
	}, nil
}

func (e *Engine) quarantineFile(ctx context.Context, params map[string]any) (ActionResult, error) {
	pathVal, ok := params["path"]
	if !ok {
		return ActionResult{}, fmt.Errorf("missing path parameter")
	}
	path, ok := pathVal.(string)
	if !ok {
		return ActionResult{}, fmt.Errorf("invalid path type: %T", pathVal)
	}

	err := sysQuarantineFile(ctx, path)
	success := err == nil
	msg := fmt.Sprintf("Quarantined file %s", path)
	if !success {
		msg = fmt.Sprintf("Failed to quarantine file %s: %v", path, err)
	}

	return ActionResult{
		Action:     ActionQuarantine,
		Success:    success,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: true, // Can be un-quarantined
	}, nil
}

func (e *Engine) isolateHost(ctx context.Context, params map[string]any) (ActionResult, error) {
	err := sysIsolateHost(ctx)
	success := err == nil
	msg := "Host isolated (management ports allowed)"
	if !success {
		msg = fmt.Sprintf("Failed to isolate host: %v", err)
	}

	return ActionResult{
		Action:     ActionIsolateHost,
		Success:    success,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: true,
	}, nil
}
