package actions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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

	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return Result{Type: ActionQuarantine, Target: sourcePath, Success: false, Error: fmt.Sprintf("generating quarantine name: %v", err)}
	}
	destPath := filepath.Join(quarantineDir, filepath.Base(sourcePath)+"."+hex.EncodeToString(token)+".quarantined")
	in, err := os.Open(sourcePath)
	if err != nil {
		return Result{Type: ActionQuarantine, Target: sourcePath, Success: false, Error: fmt.Sprintf("opening file: %v", err)}
	}
	defer in.Close()
	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Result{Type: ActionQuarantine, Target: sourcePath, Success: false, Error: fmt.Sprintf("creating quarantine file: %v", err)}
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(destPath)
		return Result{Type: ActionQuarantine, Target: sourcePath, Success: false, Error: fmt.Sprintf("copying file to quarantine: %v", err)}
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(destPath)
		return Result{Type: ActionQuarantine, Target: sourcePath, Success: false, Error: fmt.Sprintf("closing quarantine file: %v", err)}
	}
	if err := os.Remove(sourcePath); err != nil {
		_ = os.Remove(destPath)
		return Result{
			Type:    ActionQuarantine,
			Target:  sourcePath,
			Success: false,
			Error:   fmt.Sprintf("removing original file: %v", err),
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
