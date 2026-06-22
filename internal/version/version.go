// Package version provides build-time version information injected via ldflags.
package version

import (
	"fmt"
	"runtime"
)

// These variables are set at build time via -ldflags.
var (
	// Version is the semantic version of the build.
	Version = "dev"
	// Commit is the git commit hash.
	Commit = "unknown"
	// BuildTime is the UTC timestamp of the build.
	BuildTime = "unknown"
)

// Info returns a formatted version information string.
func Info() string {
	return fmt.Sprintf("r3trive %s (commit: %s, built: %s, %s/%s, go: %s)",
		Version, Commit, BuildTime, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// Short returns just the version string.
func Short() string {
	return Version
}
