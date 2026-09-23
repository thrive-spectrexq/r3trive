//go:build !windows

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
	slog.Info("executing POSIX kill", "pid", pid)
	cmd := exec.CommandContext(ctx, "kill", "-9", fmt.Sprintf("%d", pid)) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kill failed: %w, output: %s", err, string(output))
	}
	return nil
}

func sysBlockIP(ctx context.Context, ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	slog.Info("executing iptables block", "ip", ip)
	// Block both inbound traffic and outbound beacons
	cmdIn := exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP") // #nosec G204
	if out, err := cmdIn.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables block inbound failed: %w, output: %s", err, string(out))
	}
	cmdOut := exec.CommandContext(ctx, "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP") // #nosec G204
	if out, err := cmdOut.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables block outbound failed: %w, output: %s", err, string(out))
	}
	return nil
}

func sysUnblockIP(ctx context.Context, ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	slog.Info("executing iptables unblock", "ip", ip)
	_ = exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()  // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run() // #nosec G204
	return nil
}

func sysQuarantineFile(ctx context.Context, path string) error {
	slog.Info("quarantining file", "path", path)

	quarantineDir := "/var/opt/r3trive/quarantine"
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("generating quarantine name: %w", err)
	}
	destPath := filepath.Join(quarantineDir, filepath.Base(path)+"."+hex.EncodeToString(token)+".quarantined")
	if err := moveFileByCopy(path, destPath); err != nil {
		return fmt.Errorf("failed to move file to quarantine: %w", err)
	}

	cmd := exec.CommandContext(ctx, "chmod", "000", destPath) // #nosec G204
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to secure quarantined file permissions", "error", err, "output", string(out))
	}

	return nil
}

func sysUnquarantineFile(ctx context.Context, originalPath string) error {
	slog.Info("restoring quarantined file", "path", originalPath)
	quarantineDir := "/var/opt/r3trive/quarantine"
	base := filepath.Base(originalPath)

	entries, err := os.ReadDir(quarantineDir)
	if err != nil {
		return fmt.Errorf("reading quarantine directory: %w", err)
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

	if err := os.MkdirAll(filepath.Dir(originalPath), 0750); err != nil {
		return fmt.Errorf("creating restore directory: %w", err)
	}

	if err := moveFileByCopy(foundPath, originalPath); err != nil {
		return fmt.Errorf("restoring quarantined file: %w", err)
	}

	_ = exec.CommandContext(ctx, "chmod", "0640", originalPath).Run() // #nosec G204
	return nil
}

func moveFileByCopy(src, dst string) error {
	cleanSrc := filepath.Clean(src)
	cleanDst := filepath.Clean(dst)

	in, err := os.Open(cleanSrc) // #nosec G304
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600) // #nosec G304
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	return os.Remove(cleanSrc)
}

func sysIsolateHost(ctx context.Context) error {
	slog.Info("activating POSIX host isolation with pinhole rules")
	// Flush and isolate via dedicated chain
	_ = exec.CommandContext(ctx, "iptables", "-N", "R3TRIVE_ISO").Run()                                                                        // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-F", "R3TRIVE_ISO").Run()                                                                        // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-A", "R3TRIVE_ISO", "-i", "lo", "-j", "ACCEPT").Run()                                            // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-A", "R3TRIVE_ISO", "-p", "udp", "--dport", "53", "-j", "ACCEPT").Run()                          // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-A", "R3TRIVE_ISO", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run() // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-A", "R3TRIVE_ISO", "-j", "DROP").Run()                                                          // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "1", "-j", "R3TRIVE_ISO").Run()                                                    // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "1", "-j", "R3TRIVE_ISO").Run()                                                   // #nosec G204
	return nil
}

func sysUnisolateHost(ctx context.Context) error {
	slog.Info("deactivating POSIX host isolation")
	_ = exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-j", "R3TRIVE_ISO").Run()  // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-j", "R3TRIVE_ISO").Run() // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-F", "R3TRIVE_ISO").Run()                 // #nosec G204
	_ = exec.CommandContext(ctx, "iptables", "-X", "R3TRIVE_ISO").Run()                 // #nosec G204
	return nil
}
