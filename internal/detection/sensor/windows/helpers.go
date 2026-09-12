//go:build windows

package windows

import (
	"os"
)

// getHostname retrieves the local machine hostname with fallback.
func getHostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "localhost"
	}
	return name
}
