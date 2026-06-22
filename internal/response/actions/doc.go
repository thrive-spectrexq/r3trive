// Package actions contains individual response action implementations
// for each supported platform.
package actions

// TODO: Implement platform-specific response actions:
//
// Windows:
//   - kill_process: taskkill /F /PID <pid>
//   - block_ip: netsh advfirewall firewall add rule
//   - quarantine_file: Move to quarantine directory
//   - isolate_host: Windows Firewall block all except R3TRIVE
//   - disable_account: net user <name> /active:no
//   - disable_service: sc stop <name> && sc config <name> start=disabled
//
// Linux:
//   - kill_process: kill -9 <pid>
//   - block_ip: iptables -A INPUT -s <ip> -j DROP
//   - quarantine_file: mv to quarantine dir + chmod 000
//   - isolate_host: iptables rules
//   - disable_account: usermod -L <user>
//   - disable_service: systemctl stop + disable
