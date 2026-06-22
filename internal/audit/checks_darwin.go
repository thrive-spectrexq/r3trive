//go:build darwin

package audit

// getPlatformChecks returns audit checks for macOS hosts.
func getPlatformChecks() []Check {
	// TODO: Implement macOS audit checks (Gatekeeper, FileVault, firewall, etc.)
	return []Check{}
}
