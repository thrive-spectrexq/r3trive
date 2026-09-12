//go:build !windows

package hunter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func getRunningProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err == nil {
		var procs []ProcessInfo
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			commBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if err != nil {
				continue
			}
			name := strings.TrimSpace(string(commBytes))
			procs = append(procs, ProcessInfo{
				PID:  pid,
				Name: name,
			})
		}
		if len(procs) > 0 {
			return procs, nil
		}
	}

	// Fallback to ps for macOS / BSD systems where /proc does not exist
	cmd := exec.Command("ps", "-axo", "pid,comm")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	var procs []ProcessInfo
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pid, err := strconv.Atoi(fields[0])
			if err == nil {
				procs = append(procs, ProcessInfo{
					PID:  pid,
					Name: filepath.Base(fields[1]),
				})
			}
		}
	}
	return procs, nil
}
