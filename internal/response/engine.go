// Package response implements the Response Core, which executes containment
// and remediation actions in response to detected threats.
//
// See SYSTEM_ARCHITECTURE.md §4.5 for full specification.
package response

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
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
	// Inverse / Rollback actions
	ActionUnblockIP     ActionType = "unblock_ip"
	ActionUnquarantine  ActionType = "unquarantine_file"
	ActionUnisolateHost ActionType = "unisolate_host"
)

// ActionResult holds the outcome of executing a response action.
type ActionResult struct {
	Action     ActionType `json:"action"`
	Success    bool       `json:"success"`
	Message    string     `json:"message"`
	Timestamp  time.Time  `json:"timestamp"`
	Reversible bool       `json:"reversible"`
}

// AuditRecord captures an immutable record of every defensive response action attempted or executed.
type AuditRecord struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Action    ActionType     `json:"action"`
	Params    map[string]any `json:"params,omitempty"`
	DryRun    bool           `json:"dry_run"`
	Success   bool           `json:"success"`
	Error     string         `json:"error,omitempty"`
	Message   string         `json:"message,omitempty"`
}

// Engine executes response actions and manages playbooks.
type Engine struct {
	dryRun   bool
	actions  map[ActionType]ActionHandler
	mu       sync.RWMutex
	auditLog []AuditRecord
}

// ActionHandler is the function signature for action implementations.
type ActionHandler func(ctx context.Context, params map[string]any) (ActionResult, error)

// New creates a new response engine.
func New(dryRun bool) *Engine {
	e := &Engine{
		dryRun:  dryRun,
		actions: make(map[ActionType]ActionHandler),
	}

	// Register built-in actions
	e.actions[ActionKillProcess] = e.killProcess
	e.actions[ActionBlockIP] = e.blockIP
	e.actions[ActionQuarantine] = e.quarantineFile
	e.actions[ActionIsolateHost] = e.isolateHost
	// Register rollback inverse actions
	e.actions[ActionUnblockIP] = e.unblockIP
	e.actions[ActionUnquarantine] = e.unquarantineFile
	e.actions[ActionUnisolateHost] = e.unisolateHost

	return e
}

// Execute runs a response action with the given parameters.
func (e *Engine) Execute(ctx context.Context, action ActionType, params map[string]any) (ActionResult, error) {
	return e.execute(ctx, action, params, e.dryRun)
}

// ExecuteDryRun validates and simulates an action regardless of the engine mode.
func (e *Engine) ExecuteDryRun(ctx context.Context, action ActionType, params map[string]any) (ActionResult, error) {
	return e.execute(ctx, action, params, true)
}

func (e *Engine) execute(ctx context.Context, action ActionType, params map[string]any, dryRun bool) (ActionResult, error) {
	handler, ok := e.actions[action]
	if !ok {
		return ActionResult{}, fmt.Errorf("unknown action type: %s", action)
	}

	// Validate parameters before dry-run check so invalid inputs are always rejected
	if err := e.validateParams(action, params); err != nil {
		return ActionResult{}, err
	}

	record := AuditRecord{
		ID:        fmt.Sprintf("audit_%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Params:    params,
		DryRun:    dryRun,
	}

	if dryRun {
		slog.Info("dry-run: would execute action", "action", action, "params", params)
		res := ActionResult{
			Action:    action,
			Success:   true,
			Message:   fmt.Sprintf("[DRY-RUN] Would execute %s", action),
			Timestamp: time.Now().UTC(),
		}
		record.Success = true
		record.Message = res.Message
		e.recordAudit(record)
		return res, nil
	}

	result, err := handler(ctx, params)
	if err != nil {
		slog.Error("action failed", "action", action, "error", err)
		record.Success = false
		record.Error = err.Error()
		e.recordAudit(record)
		return result, err
	}

	record.Success = result.Success
	record.Message = result.Message
	e.recordAudit(record)

	slog.Info("action executed", "action", action, "success", result.Success)
	return result, nil
}

func (e *Engine) recordAudit(r AuditRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.auditLog = append(e.auditLog, r)
	slog.Info("defense action audit",
		"audit_id", r.ID,
		"action", r.Action,
		"dry_run", r.DryRun,
		"success", r.Success,
		"error", r.Error,
	)
}

// AuditLog returns a snapshot copy of the defensive response audit log.
func (e *Engine) AuditLog() []AuditRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	records := make([]AuditRecord, len(e.auditLog))
	copy(records, e.auditLog)
	return records
}

// validateParams validates the parameters for a given action type without executing.
func (e *Engine) validateParams(action ActionType, params map[string]any) error {
	switch action {
	case ActionKillProcess:
		pidVal, ok := params["pid"]
		if !ok {
			return fmt.Errorf("missing pid parameter")
		}
		var pid int
		switch v := pidVal.(type) {
		case int:
			pid = v
		case float64:
			pid = int(v)
		case int64:
			pid = int(v)
		default:
			return fmt.Errorf("invalid pid type: %T", pidVal)
		}
		if pid <= 0 {
			return fmt.Errorf("invalid pid: %d (must be positive)", pid)
		}
		if pid == 1 {
			return fmt.Errorf("defensive guardrail: killing system init process pid 1 is prohibited")
		}
		if nameVal, ok := params["process_name"]; ok {
			if name, ok := nameVal.(string); ok && isProtectedProcess(name) {
				return fmt.Errorf("defensive guardrail: killing critical system process %s is prohibited", name)
			}
		}
	case ActionBlockIP:
		ipVal, ok := params["ip"]
		if !ok {
			return fmt.Errorf("missing ip parameter")
		}
		ip, ok := ipVal.(string)
		if !ok {
			return fmt.Errorf("invalid ip type: %T", ipVal)
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address: %q", ip)
		}
		if ip == "127.0.0.1" || ip == "localhost" {
			return fmt.Errorf("defensive guardrail: blocking localhost (%s) is prohibited", ip)
		}
	case ActionQuarantine:
		pathVal, ok := params["path"]
		if !ok {
			return fmt.Errorf("missing path parameter")
		}
		if _, ok := pathVal.(string); !ok {
			return fmt.Errorf("invalid path type: %T", pathVal)
		}
	case ActionUnblockIP:
		ipVal, ok := params["ip"]
		if !ok {
			return fmt.Errorf("missing ip parameter")
		}
		if _, ok := ipVal.(string); !ok {
			return fmt.Errorf("invalid ip type: %T", ipVal)
		}
	case ActionUnquarantine:
		pathVal, ok := params["path"]
		if !ok {
			return fmt.Errorf("missing path parameter")
		}
		if _, ok := pathVal.(string); !ok {
			return fmt.Errorf("invalid path type: %T", pathVal)
		}
	case ActionUnisolateHost:
		// No required parameters
	case ActionIsolateHost:
		if targetVal, ok := params["target"]; ok {
			if s, ok := targetVal.(string); ok && (s == "127.0.0.1" || s == "localhost") {
				return fmt.Errorf("defensive guardrail: isolating localhost (%s) is prohibited", s)
			}
		}
		if ipVal, ok := params["ip"]; ok {
			if s, ok := ipVal.(string); ok && (s == "127.0.0.1" || s == "localhost") {
				return fmt.Errorf("defensive guardrail: isolating localhost (%s) is prohibited", s)
			}
		}
	}
	return nil
}

func isProtectedProcess(name string) bool {
	lower := strings.ToLower(filepath.Base(name))
	protected := map[string]bool{
		"csrss.exe":    true,
		"lsass.exe":    true,
		"services.exe": true,
		"smss.exe":     true,
		"wininit.exe":  true,
		"systemd":      true,
		"init":         true,
		"sshd":         true,
		"dbus-daemon":  true,
		"kthreadd":     true,
	}
	return protected[lower]
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

	if pid <= 0 {
		return ActionResult{}, fmt.Errorf("invalid pid: %d (must be positive)", pid)
	}

	err := sysKillProcess(ctx, pid)
	success := err == nil
	msg := fmt.Sprintf("Killed process %d", pid)
	if !success {
		msg = fmt.Sprintf("Failed to kill process %d: %v", pid, err)
	}

	result := ActionResult{
		Action:     ActionKillProcess,
		Success:    success,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: false,
	}
	if err != nil {
		return result, fmt.Errorf("kill process %d: %w", pid, err)
	}
	return result, nil
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

	result := ActionResult{
		Action:     ActionBlockIP,
		Success:    success,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: true,
	}
	if err != nil {
		return result, fmt.Errorf("block IP %s: %w", ip, err)
	}
	return result, nil
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

	result := ActionResult{
		Action:     ActionQuarantine,
		Success:    success,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: true, // Can be un-quarantined
	}
	if err != nil {
		return result, fmt.Errorf("quarantine file %s: %w", path, err)
	}
	return result, nil
}

func (e *Engine) isolateHost(ctx context.Context, params map[string]any) (ActionResult, error) {
	err := sysIsolateHost(ctx)
	if err != nil {
		result := ActionResult{
			Action:     ActionIsolateHost,
			Success:    false,
			Message:    fmt.Sprintf("Failed to isolate host: %v", err),
			Timestamp:  time.Now().UTC(),
			Reversible: true,
		}
		return result, err
	}

	return ActionResult{
		Action:     ActionIsolateHost,
		Success:    true,
		Message:    "Host isolated (management ports allowed)",
		Timestamp:  time.Now().UTC(),
		Reversible: true,
	}, nil
}

func (e *Engine) unblockIP(ctx context.Context, params map[string]any) (ActionResult, error) {
	ip := params["ip"].(string)
	err := sysUnblockIP(ctx, ip)
	msg := fmt.Sprintf("Unblocked IP %s", ip)
	if err != nil {
		msg = fmt.Sprintf("Failed to unblock IP %s: %v", ip, err)
	}
	return ActionResult{
		Action:     ActionUnblockIP,
		Success:    err == nil,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: false,
	}, err
}

func (e *Engine) unquarantineFile(ctx context.Context, params map[string]any) (ActionResult, error) {
	path := params["path"].(string)
	err := sysUnquarantineFile(ctx, path)
	msg := fmt.Sprintf("Restored quarantined file %s", path)
	if err != nil {
		msg = fmt.Sprintf("Failed to restore quarantined file %s: %v", path, err)
	}
	return ActionResult{
		Action:     ActionUnquarantine,
		Success:    err == nil,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: false,
	}, err
}

func (e *Engine) unisolateHost(ctx context.Context, params map[string]any) (ActionResult, error) {
	err := sysUnisolateHost(ctx)
	msg := "Host isolation removed"
	if err != nil {
		msg = fmt.Sprintf("Failed to remove host isolation: %v", err)
	}
	return ActionResult{
		Action:     ActionUnisolateHost,
		Success:    err == nil,
		Message:    msg,
		Timestamp:  time.Now().UTC(),
		Reversible: false,
	}, err
}
