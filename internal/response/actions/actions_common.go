package actions

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// ActionType defines supported automated containment actions.
type ActionType string

const (
	ActionKillProcess    ActionType = "kill_process"
	ActionBlockIP        ActionType = "block_ip"
	ActionQuarantine     ActionType = "quarantine_file"
	ActionIsolateHost    ActionType = "isolate_host"
	ActionDisableAccount ActionType = "disable_account"
)

// Result holds the status of an executed containment action.
type Result struct {
	Type    ActionType `json:"type"`
	Target  string     `json:"target"`
	Success bool       `json:"success"`
	Detail  string     `json:"detail,omitempty"`
	Error   string     `json:"error,omitempty"`
}

// QuarantineFile safely relocates a suspicious file to a restricted quarantine directory.
func QuarantineFile(ctx context.Context, sourcePath string, quarantineDir string) Result {
	if quarantineDir == "" {
		quarantineDir = filepath.Join(os.TempDir(), "r3trive_quarantine")
	}

	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return Result{
			Type:    ActionQuarantine,
			Target:  sourcePath,
			Success: false,
			Error:   fmt.Sprintf("creating quarantine dir: %v", err),
		}
	}

	destPath := filepath.Join(quarantineDir, filepath.Base(sourcePath)+".quarantined")
	if err := os.Rename(sourcePath, destPath); err != nil {
		return Result{
			Type:    ActionQuarantine,
			Target:  sourcePath,
			Success: false,
			Error:   fmt.Sprintf("moving file to quarantine: %v", err),
		}
	}

	// Remove all read/write/execute permissions from quarantined file
	_ = os.Chmod(destPath, 0000)

	slog.Warn("file quarantined successfully", "source", sourcePath, "destination", destPath)
	return Result{
		Type:    ActionQuarantine,
		Target:  sourcePath,
		Success: true,
		Detail:  fmt.Sprintf("Relocated to %s with 0000 permissions", destPath),
	}
}
