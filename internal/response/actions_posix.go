//go:build !windows

package response

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
)

func sysKillProcess(ctx context.Context, pid int) error {
	slog.Info("executing POSIX kill", "pid", pid)
	cmd := exec.CommandContext(ctx, "kill", "-9", fmt.Sprintf("%d", pid)) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kill failed: %w, output: %s", err, string(output))
	}
	return nil
}

func sysBlockIP(ctx context.Context, ip string) error {
	if parsedIP := net.ParseIP(ip); parsedIP == nil {
		return fmt.Errorf("invalid IP address for blocking: %q", ip)
	}
	slog.Info("executing iptables block", "ip", ip)
	cmd := exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP") // #nosec G204
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables block failed: %w, output: %s", err, string(out))
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
		// Fallback for cross-device move (EXDEV) or rename failure: copy and remove original
		if copyErr := moveFileByCopy(path, destPath); copyErr != nil {
			return fmt.Errorf("failed to move file to quarantine (rename: %v, copy: %w)", err, copyErr)
		}
	}

	cmd := exec.CommandContext(ctx, "chmod", "000", destPath) // #nosec G204
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to secure quarantined file permissions", "error", err, "output", string(out))
	}

	return nil
}

func moveFileByCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	return os.Remove(src)
}

func sysIsolateHost(ctx context.Context) error {
	slog.Warn("Host isolation requested but disabled for safety")
	return fmt.Errorf("host isolation is disabled by default for safety")
}
