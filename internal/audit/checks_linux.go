//go:build !windows && !darwin

package audit

// getPlatformChecks returns audit checks for Linux hosts.
func getPlatformChecks() []Check {
	// TODO: Implement Linux audit checks (iptables, SSH config, users, etc.)
	return []Check{}
}
