//go:build windows

package response

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("generating quarantine name: %w", err)
	}
	destPath := filepath.Join(quarantineDir, filepath.Base(path)+"."+hex.EncodeToString(token)+".quarantined")
	in, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening source file: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("creating quarantine file: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(destPath)
		return fmt.Errorf("copying file to quarantine: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("closing quarantine file: %w", err)
	}
	if err := os.Remove(path); err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("removing source file: %w", err)
	}

	// Remove permissions (icacls to deny everything or just restrict to SYSTEM)
	cmd := exec.CommandContext(ctx, "icacls", destPath, "/inheritance:r", "/grant:r", "SYSTEM:(F)")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("quarantined file moved but permissions not secured: %w (output: %s)", err, string(out))
	}

	return nil
}

func sysUnblockIP(ctx context.Context, ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	slog.Info("executing Windows Firewall unblock", "ip", ip)
	ruleName := fmt.Sprintf("R3TRIVE-BLOCK-%s", ip)

	// Delete inbound & outbound rules
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName+"-IN").Run()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName+"-OUT").Run()

	return nil
}

func sysUnquarantineFile(ctx context.Context, originalPath string) error {
	slog.Info("restoring quarantined file", "path", originalPath)
	quarantineDir := `C:\ProgramData\R3trive\Quarantine`
	base := filepath.Base(originalPath)

	entries, err := os.ReadDir(quarantineDir)
	if err != nil {
		return fmt.Errorf("reading quarantine dir: %w", err)
	}

	var foundPath string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), base+".") && strings.HasSuffix(entry.Name(), ".quarantined") {
			foundPath = filepath.Join(quarantineDir, entry.Name())
			break
		}
	}

	if foundPath == "" {
		return fmt.Errorf("quarantined file for %s not found", originalPath)
	}

	// Restore file
	in, err := os.Open(foundPath)
	if err != nil {
		return fmt.Errorf("opening quarantined file: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(originalPath), 0750); err != nil {
		return fmt.Errorf("creating target directory: %w", err)
	}

	out, err := os.OpenFile(originalPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("restoring original file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copying restored file: %w", err)
	}

	_ = in.Close()
	_ = os.Remove(foundPath)
	return nil
}

func sysIsolateHost(ctx context.Context) error {
	slog.Info("activating host isolation with administrative pinhole")
	// Block general outbound
	cmdBlock := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=R3TRIVE-ISOLATE-OUT", "dir=out", "action=block")
	if out, err := cmdBlock.CombinedOutput(); err != nil {
		return fmt.Errorf("isolation rule creation failed: %w, output: %s", err, string(out))
	}

	// Allow loopback and DNS so management agent retains connectivity
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=R3TRIVE-ISOLATE-DNS", "dir=out", "action=allow", "protocol=UDP", "remoteport=53").Run()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=R3TRIVE-ISOLATE-LOOPBACK", "dir=out", "action=allow", "remoteip=127.0.0.1").Run()

	return nil
}

func sysUnisolateHost(ctx context.Context) error {
	slog.Info("deactivating host isolation")
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name=R3TRIVE-ISOLATE-OUT").Run()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name=R3TRIVE-ISOLATE-DNS").Run()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name=R3TRIVE-ISOLATE-LOOPBACK").Run()
	return nil
}
