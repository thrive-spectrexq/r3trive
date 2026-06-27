//go:build !windows && !darwin

package audit

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// getPlatformChecks returns audit checks for Linux hosts.
func getPlatformChecks() []Check {
	return []Check{
		&sshCheck{},
		&firewallCheck{},
		&aslrCheck{},
		&macCheck{},
	}
}

// sshCheck verifies SSH root login is disabled
type sshCheck struct{}

func (c *sshCheck) Name() string     { return "SSH Root Login Disabled" }
func (c *sshCheck) Category() string { return "Remote Access" }
func (c *sshCheck) Run() CheckResult {
	b, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		if os.IsNotExist(err) {
			return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "SSH is not installed or configured"}
		}
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: fmt.Sprintf("Could not read sshd_config: %v", err)}
	}

	lines := strings.Split(string(b), "\n")
	rootLogin := "prohibit-password" // default
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PermitRootLogin") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				rootLogin = parts[1]
			}
		}
	}

	if strings.ToLower(rootLogin) == "yes" {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusFail, Detail: "Root login is permitted via SSH", Remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config"}
	}

	return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: fmt.Sprintf("Root login is set to %s", rootLogin)}
}

// firewallCheck verifies a firewall is active
type firewallCheck struct{}

func (c *firewallCheck) Name() string     { return "Linux Firewall Status" }
func (c *firewallCheck) Category() string { return "Firewall" }
func (c *firewallCheck) Run() CheckResult {
	// try ufw first
	out, err := exec.Command("ufw", "status").CombinedOutput()
	if err == nil {
		if strings.Contains(string(out), "Status: active") {
			return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "UFW is active"}
		}
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusFail, Detail: "UFW is installed but inactive", Remediation: "Run ufw enable"}
	}

	// try iptables
	_, err = exec.Command("iptables", "-L").CombinedOutput()
	if err == nil {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "iptables is accessible (rules not analyzed deeply)"}
	}

	return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: "Could not determine firewall status (ufw/iptables command failed or not found)"}
}

// aslrCheck verifies ASLR is enabled
type aslrCheck struct{}

func (c *aslrCheck) Name() string     { return "ASLR Enabled" }
func (c *aslrCheck) Category() string { return "Kernel" }
func (c *aslrCheck) Run() CheckResult {
	b, err := os.ReadFile("/proc/sys/kernel/randomize_va_space")
	if err != nil {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: fmt.Sprintf("Could not read ASLR status: %v", err)}
	}

	val := strings.TrimSpace(string(b))
	if val == "2" {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "ASLR is fully enabled (value: 2)"}
	} else if val == "1" {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: "ASLR is partially enabled (value: 1)"}
	}

	return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusFail, Detail: "ASLR is disabled", Remediation: "sysctl -w kernel.randomize_va_space=2"}
}

// macCheck verifies MAC (AppArmor/SELinux) is enforcing
type macCheck struct{}

func (c *macCheck) Name() string     { return "Mandatory Access Control" }
func (c *macCheck) Category() string { return "Access Control" }
func (c *macCheck) Run() CheckResult {
	// Check SELinux
	out, err := exec.Command("getenforce").CombinedOutput()
	if err == nil {
		val := strings.TrimSpace(string(out))
		if val == "Enforcing" {
			return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "SELinux is Enforcing"}
		}
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusFail, Detail: fmt.Sprintf("SELinux is %s", val), Remediation: "Set SELinux to Enforcing"}
	}

	// Check AppArmor
	_, err = exec.Command("apparmor_status").CombinedOutput()
	if err == nil {
		return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusPass, Detail: "AppArmor is enabled and loaded"}
	}

	return CheckResult{Name: c.Name(), Category: c.Category(), Status: StatusWarn, Detail: "Neither SELinux nor AppArmor appear to be active"}
}
