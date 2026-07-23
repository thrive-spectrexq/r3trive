//go:build darwin

package audit

import (
	"os/exec"
	"strings"
)

// getPlatformChecks returns audit checks for macOS hosts.
func getPlatformChecks() []Check {
	return []Check{
		&gatekeeperCheck{},
		&fileVaultCheck{},
		&macOSFirewallCheck{},
	}
}

// gatekeeperCheck verifies Gatekeeper status on macOS
type gatekeeperCheck struct{}

func (c *gatekeeperCheck) Name() string     { return "Gatekeeper Status" }
func (c *gatekeeperCheck) Category() string { return "System Integrity" }
func (c *gatekeeperCheck) Run() CheckResult {
	out, err := exec.Command("spctl", "--status").CombinedOutput()
	if err != nil {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: "Could not query Gatekeeper status"}
	}
	if strings.Contains(string(out), "assessments enabled") {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "Gatekeeper is enabled"}
	}
	return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusFail, Detail: "Gatekeeper is disabled", Remediation: "Run 'sudo spctl --master-enable'"}
}

// fileVaultCheck verifies FileVault disk encryption on macOS
type fileVaultCheck struct{}

func (c *fileVaultCheck) Name() string     { return "FileVault Encryption" }
func (c *fileVaultCheck) Category() string { return "Storage Encryption" }
func (c *fileVaultCheck) Run() CheckResult {
	out, err := exec.Command("fdesetup", "status").CombinedOutput()
	if err != nil {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: "Could not query FileVault status"}
	}
	if strings.Contains(string(out), "FileVault is On") {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "FileVault encryption is enabled"}
	}
	return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusFail, Detail: "FileVault is disabled", Remediation: "Enable FileVault in System Settings"}
}

// macOSFirewallCheck verifies application firewall on macOS
type macOSFirewallCheck struct{}

func (c *macOSFirewallCheck) Name() string     { return "macOS Firewall Status" }
func (c *macOSFirewallCheck) Category() string { return "Firewall" }
func (c *macOSFirewallCheck) Run() CheckResult {
	out, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").CombinedOutput()
	if err != nil {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: "Could not query macOS firewall state"}
	}
	if strings.Contains(string(out), "enabled") {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "Application Firewall is enabled"}
	}
	return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusFail, Detail: "Application Firewall is disabled", Remediation: "Enable Firewall in System Settings"}
}
