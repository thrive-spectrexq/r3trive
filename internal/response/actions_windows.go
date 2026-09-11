//go:build windows

package response

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
)

func sysKillProcess(ctx context.Context, pid int) error {
	slog.Info("executing Windows taskkill", "pid", pid)
	cmd := exec.CommandContext(ctx, "taskkill.exe", "/F", "/PID", fmt.Sprintf("%d", pid))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("taskkill failed: %w, output: %s", err, string(output))
	}
	return nil
}

func sysBlockIP(ctx context.Context, ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	slog.Info("executing Windows Firewall block", "ip", ip)
	ruleName := fmt.Sprintf("R3TRIVE-BLOCK-%s", ip)

	// Block inbound
	cmdIn := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName+"-IN", "dir=in", "action=block", "remoteip="+ip)
	if out, err := cmdIn.CombinedOutput(); err != nil {
		return fmt.Errorf("firewall block inbound failed: %w, output: %s", err, string(out))
	}

	// Block outbound
	cmdOut := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName+"-OUT", "dir=out", "action=block", "remoteip="+ip)
	if out, err := cmdOut.CombinedOutput(); err != nil {
		return fmt.Errorf("firewall block outbound failed: %w, output: %s", err, string(out))
	}

	return nil
}

func sysQuarantineFile(ctx context.Context, path string) error {
	slog.Info("quarantining file", "path", path)

	// Ensure quarantine dir exists
	quarantineDir := `C:\ProgramData\R3trive\Quarantine`
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	// Move file
	fileName := filepath.Base(path)
	destPath := filepath.Join(quarantineDir, fileName+".quarantined")

	if err := os.Rename(path, destPath); err != nil {
		// Fallback: try to copy and delete if cross-device rename fails,
		// but simple rename usually works if not locked.
		return fmt.Errorf("failed to move file to quarantine: %w", err)
	}

	// Remove permissions (icacls to deny everything or just restrict to SYSTEM)
	cmd := exec.CommandContext(ctx, "icacls", destPath, "/inheritance:r", "/grant:r", "SYSTEM:(F)")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("quarantined file moved but permissions not secured: %w (output: %s)", err, string(out))
	}

	return nil
}

func sysIsolateHost(ctx context.Context) error {
	slog.Warn("Host isolation requested but disabled for safety")
	return fmt.Errorf("host isolation is disabled by default for safety")
}
