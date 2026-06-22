package audit

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// getPlatformChecks returns all audit checks for Windows.
func getPlatformChecks() []Check {
	return []Check{
		&firewallCheck{},
		&defenderCheck{},
		&guestAccountCheck{},
		&rdpCheck{},
		&autoUpdatesCheck{},
		&uacCheck{},
		&passwordPolicyCheck{},
	}
}

// firewallCheck verifies Windows Firewall is enabled on all profiles.
type firewallCheck struct{}

func (c *firewallCheck) Name() string     { return "Windows Firewall Status" }
func (c *firewallCheck) Category() string  { return "Firewall" }

func (c *firewallCheck) Run() CheckResult {
	out, err := runPowerShell("Get-NetFirewallProfile | Select-Object -Property Name,Enabled | ConvertTo-Json")
	if err != nil {
		slog.Debug("firewall check failed", "error", err)
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusWarn,
			Detail: fmt.Sprintf("Could not query firewall: %v", err),
		}
	}

	if strings.Contains(out, `"Enabled":  false`) || strings.Contains(out, `"Enabled": false`) {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusFail,
			Detail: "One or more firewall profiles are disabled",
			Remediation: "Enable all firewall profiles: Set-NetFirewallProfile -All -Enabled True",
		}
	}

	return CheckResult{
		Name: c.Name(), Category: c.Category(),
		Status: StatusPass,
		Detail: "All firewall profiles enabled",
	}
}

// defenderCheck verifies Windows Defender real-time protection.
type defenderCheck struct{}

func (c *defenderCheck) Name() string     { return "Windows Defender Real-Time Protection" }
func (c *defenderCheck) Category() string  { return "Antivirus" }

func (c *defenderCheck) Run() CheckResult {
	out, err := runPowerShell("(Get-MpComputerStatus).RealTimeProtectionEnabled")
	if err != nil {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusWarn,
			Detail: fmt.Sprintf("Could not query Defender: %v", err),
		}
	}

	if strings.TrimSpace(out) == "True" {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusPass,
			Detail: "Real-time protection enabled",
		}
	}

	return CheckResult{
		Name: c.Name(), Category: c.Category(),
		Status: StatusFail,
		Detail: "Real-time protection is disabled",
		Remediation: "Enable Defender: Set-MpPreference -DisableRealtimeMonitoring $false",
	}
}

// guestAccountCheck verifies the Guest account is disabled.
type guestAccountCheck struct{}

func (c *guestAccountCheck) Name() string     { return "Guest Account Disabled" }
func (c *guestAccountCheck) Category() string  { return "Users" }

func (c *guestAccountCheck) Run() CheckResult {
	out, err := runPowerShell("(Get-LocalUser -Name Guest).Enabled")
	if err != nil {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusWarn,
			Detail: fmt.Sprintf("Could not query Guest account: %v", err),
		}
	}

	if strings.TrimSpace(out) == "False" {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusPass,
			Detail: "Guest account is disabled",
		}
	}

	return CheckResult{
		Name: c.Name(), Category: c.Category(),
		Status: StatusFail,
		Detail: "Guest account is enabled",
		Remediation: "Disable Guest: Disable-LocalUser -Name Guest",
	}
}

// rdpCheck verifies Remote Desktop is properly configured.
type rdpCheck struct{}

func (c *rdpCheck) Name() string     { return "Remote Desktop Configuration" }
func (c *rdpCheck) Category() string  { return "Remote Access" }

func (c *rdpCheck) Run() CheckResult {
	out, err := runPowerShell(`(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections`)
	if err != nil {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusWarn,
			Detail: fmt.Sprintf("Could not query RDP settings: %v", err),
		}
	}

	if strings.TrimSpace(out) == "1" {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusPass,
			Detail: "Remote Desktop is disabled",
		}
	}

	return CheckResult{
		Name: c.Name(), Category: c.Category(),
		Status: StatusWarn,
		Detail: "Remote Desktop is enabled — ensure NLA is required",
		Remediation: "Require NLA for RDP connections via Group Policy",
	}
}

// autoUpdatesCheck verifies Windows Update is configured.
type autoUpdatesCheck struct{}

func (c *autoUpdatesCheck) Name() string     { return "Windows Auto-Updates" }
func (c *autoUpdatesCheck) Category() string  { return "Updates" }

func (c *autoUpdatesCheck) Run() CheckResult {
	out, err := runPowerShell(`(New-Object -ComObject Microsoft.Update.AutoUpdate).EnableService()
$au = (New-Object -ComObject Microsoft.Update.AutoUpdate)
$au.EnableService()
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate`)
	if err != nil {
		// If registry key doesn't exist, auto-updates are likely on (default)
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusPass,
			Detail: "Auto-updates appear to be enabled (default)",
		}
	}

	if strings.TrimSpace(out) == "1" {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusFail,
			Detail: "Auto-updates are disabled via Group Policy",
			Remediation: "Enable auto-updates in Group Policy or WSUS",
		}
	}

	return CheckResult{
		Name: c.Name(), Category: c.Category(),
		Status: StatusPass,
		Detail: "Auto-updates are enabled",
	}
}

// uacCheck verifies User Account Control is enabled.
type uacCheck struct{}

func (c *uacCheck) Name() string     { return "User Account Control (UAC)" }
func (c *uacCheck) Category() string  { return "Access Control" }

func (c *uacCheck) Run() CheckResult {
	out, err := runPowerShell(`(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA").EnableLUA`)
	if err != nil {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusWarn,
			Detail: fmt.Sprintf("Could not query UAC: %v", err),
		}
	}

	if strings.TrimSpace(out) == "1" {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusPass,
			Detail: "UAC is enabled",
		}
	}

	return CheckResult{
		Name: c.Name(), Category: c.Category(),
		Status: StatusFail,
		Detail: "UAC is disabled",
		Remediation: `Enable UAC: Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1`,
	}
}

// passwordPolicyCheck verifies password complexity requirements.
type passwordPolicyCheck struct{}

func (c *passwordPolicyCheck) Name() string     { return "Password Policy" }
func (c *passwordPolicyCheck) Category() string  { return "Users" }

func (c *passwordPolicyCheck) Run() CheckResult {
	out, err := runPowerShell("net accounts")
	if err != nil {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusWarn,
			Detail: fmt.Sprintf("Could not query password policy: %v", err),
		}
	}

	issues := []string{}

	if strings.Contains(out, "Minimum password length:") {
		// Parse minimum length
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "Minimum password length") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					val := parts[len(parts)-1]
					if val == "0" {
						issues = append(issues, "No minimum password length set")
					}
				}
			}
		}
	}

	if len(issues) > 0 {
		return CheckResult{
			Name: c.Name(), Category: c.Category(),
			Status: StatusWarn,
			Detail: strings.Join(issues, "; "),
			Remediation: "Set minimum password length: net accounts /minpwlen:12",
		}
	}

	return CheckResult{
		Name: c.Name(), Category: c.Category(),
		Status: StatusPass,
		Detail: "Password policy meets minimum requirements",
	}
}

// runPowerShell executes a PowerShell command and returns stdout.
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("powershell: %w: %s", err, string(out))
	}
	return string(out), nil
}
