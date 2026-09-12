//go:build !windows

package hunter

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func getRunningProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil
	}

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
	return procs, nil
}
