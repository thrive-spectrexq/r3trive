//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"strconv"
)

// getHostname retrieves the local machine hostname with fallback.
func getHostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "localhost"
	}
	return name
}

// extractNameFromPath extracts the base file or executable name from a full path.
func extractNameFromPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

// toInt converts an interface or numerical type to int.
func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	case uint:
		return int(val)
	case uint32:
		return int(val)
	case uint64:
		return int(val)
	case float64:
		return int(val)
	case float32:
		return int(val)
	case string:
		n, err := strconv.Atoi(val)
		if err == nil {
			return n
		}
	}
	return 0
}
