//go:build !windows

package response

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

func sysKillProcess(ctx context.Context, pid int) error {
	slog.Info("executing POSIX kill", "pid", pid)
	cmd := exec.CommandContext(ctx, "kill", "-9", fmt.Sprintf("%d", pid)) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kill failed: %v, output: %s", err, string(output))
	}
	return nil
}

func sysBlockIP(ctx context.Context, ip string) error {
	slog.Info("executing iptables block", "ip", ip)
	cmd := exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP") // #nosec G204
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables block failed: %v, output: %s", err, string(out))
	}
	return nil
}

func sysQuarantineFile(ctx context.Context, path string) error {
	slog.Info("quarantining file", "path", path)
	
	quarantineDir := "/var/opt/r3trive/quarantine"
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	fileName := filepath.Base(path)
	destPath := filepath.Join(quarantineDir, fileName+".quarantined")
	
	if err := os.Rename(path, destPath); err != nil {
		return fmt.Errorf("failed to move file to quarantine: %w", err)
	}

	cmd := exec.CommandContext(ctx, "chmod", "000", destPath) // #nosec G204
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to secure quarantined file permissions", "error", err, "output", string(out))
	}

	return nil
}

func sysIsolateHost(ctx context.Context) error {
	slog.Warn("Host isolation requested but disabled for safety")
	return fmt.Errorf("Host isolation is disabled by default for safety. Must be explicitly enabled with allowed management ports.")
}
