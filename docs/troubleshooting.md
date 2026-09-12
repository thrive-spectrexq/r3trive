# Troubleshooting Guide

This guide provides diagnostic steps, prerequisite requirements, and remediation actions for common operational scenarios across Windows, Linux, and macOS environments in R3TRIVE.

---

## Table of Contents

1. [Windows Sensors and Privileges](#1-windows-sensors-and-privileges)
2. [Linux eBPF and Kernel Requirements](#2-linux-ebpf-and-kernel-requirements)
3. [macOS Endpoint Security Framework (ESF)](#3-macos-endpoint-security-framework-esf)
4. [Memory Locking and Process Hardening](#4-memory-locking-and-process-hardening)
5. [Anomaly Detection Tuning](#5-anomaly-detection-tuning)
6. [Plugin Diagnostics](#6-plugin-diagnostics)

---

## 1. Windows Sensors and Privileges

### Unprivileged Process and Network Sensors
R3TRIVE implements native Windows sensors that operate without administrative privileges:
- **Process Sensor**: Leverages the Windows Toolhelp32 snapshot API (`CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`). This works across all user accounts.
- **Network Sensor**: Leverages `iphlpapi.dll` table enumeration (`GetExtendedTcpTable`, `GetExtendedUdpTable`). This allows unprivileged processes to inspect their own and system connection states.
- **Service Sensor**: Uses the Windows Service Control Manager (`OpenSCManager`, `EnumServicesStatusEx`). Unprivileged tokens can read service statuses with `SC_MANAGER_ENUMERATE_SERVICE`.

### Elevated Privileges Required
Certain telemetry streams require administrative or `SeDebugPrivilege` access:
- **Full Memory Inspection**: Attempting to read virtual memory of protected processes (`lsass.exe`, `csrss.exe`) will return `ERROR_ACCESS_DENIED` (5) unless running with elevated debug rights.
- **Registry Machine Hives**: Writing or attaching real-time change notifications to protected system hives (e.g. `HKEY_LOCAL_MACHINE\SAM`, `HKEY_LOCAL_MACHINE\SECURITY`) requires `NT AUTHORITY\SYSTEM`.

### Diagnostic Commands (PowerShell)
```powershell
# Check if running elevated
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Verify service manager accessibility
Get-Service -Name "r3trive" -ErrorAction SilentlyContinue
```

---

## 2. Linux eBPF and Kernel Requirements

### Kernel Version and CO-RE Support
R3TRIVE utilizes Compile Once, Run Everywhere (CO-RE) eBPF technology on Linux:
- **Minimum Recommended Kernel**: Linux 5.4 or higher.
- **BTF Support**: Requires BTF (BPF Type Format) enabled in kernel configuration (`CONFIG_DEBUG_INFO_BTF=y`).
- **Inspection Path**: Check for `/sys/kernel/btf/vmlinux`.

### Automatic /proc Fallback
If R3TRIVE detects that the host kernel does not support BTF or is older than 5.4, it automatically logs a warning and falls back to user-space `/proc` polling and netlink sockets:
```
WARN linux ebpf co-re unavailable; falling back to /proc polling kernel_version=4.19 btf=false
```

### Required Linux Capabilities
When running in containerized or non-root environments, grant the following capabilities:
- `CAP_BPF` (or `CAP_SYS_ADMIN` on kernels < 5.8)
- `CAP_PERFMON`
- `CAP_NET_ADMIN`
- `CAP_IPC_LOCK` (for ring buffer allocations)

### Diagnostic Commands (Linux Shell)
```bash
# Check kernel version
uname -r

# Verify BTF support
ls -lh /sys/kernel/btf/vmlinux

# Check BPF filesystem mount
mount | grep bpf
```

---

## 3. macOS Endpoint Security Framework (ESF)

### System Entitlements and Full Disk Access
The macOS sensor requires the Endpoint Security entitlement (`com.apple.developer.endpoint-security.client`):
- Production builds signed with Apple Developer ID certificates with the ESF entitlement enabled.
- The binary or host terminal application must be granted **Full Disk Access** in **System Settings > Privacy & Security > Full Disk Access**.

### Fallback Mode
When running on macOS development machines without the ESF entitlement or without root privileges, R3TRIVE falls back to user-space `sysctl`, `lsof`, and `kqueue` monitoring.

### Diagnostic Commands (macOS zsh)
```bash
# Verify code signature and entitlements
codesign -d --entitlements - /usr/local/bin/r3trive

# Test process enumeration fallback
ps -eo pid,ppid,comm,args
```

---

## 4. Memory Locking and Process Hardening

### VirtualLock and mlock Operations
R3TRIVE implements anti-swapping and memory-scrubbing primitives to protect in-memory credentials, encryption keys, and IOC patterns:
- **Windows**: Calls `VirtualLock` on sensitive buffers to prevent paging to `pagefile.sys`.
- **POSIX (Linux/macOS)**: Calls `unix.Mlock` to prevent swapping to swap partitions or files.

### Common Error: Resource Limit Exceeded (ENOMEM / EPERM)
On Linux, `unix.Mlock` will return `ENOMEM` or `EPERM` if the process exceeds `RLIMIT_MEMLOCK`.

### Remediation:
1. Check current limits:
   ```bash
   ulimit -l
   ```
2. Increase limits in `/etc/security/limits.conf`:
   ```text
   r3trive  soft  memlock  65536
   r3trive  hard  memlock  131072
   ```
3. In systemd service units, configure:
   ```ini
   LimitMEMLOCK=infinity
   ```

---

## 5. Anomaly Detection Tuning

R3TRIVE includes statistical and heuristic anomaly detectors. The default thresholds are tuned for standard enterprise environments:

### C2 Beaconing Detector
- **Metric**: Coefficient of Variation (CV = sigma / mu) of network connection inter-arrival intervals.
- **Default Threshold**: CV < 0.15 with minimum 5 events.
- **Symptom**: Legitimate scheduled tasks or telemetry beacons flagging as C2.
- **Tuning**: Increase the minimum event count or allowlist trusted destination FQDNs/IPs in the configuration.

### DNS Tunneling Detector
- **Metric**: Shannon Entropy of subdomains and request rate per domain.
- **Default Threshold**: Shannon Entropy > 3.8 bits/byte.
- **Symptom**: Content delivery networks (CDNs) or cloud service subdomains with high randomness triggering alerts.
- **Tuning**: Adjust the entropy threshold to 4.2 or configure domain exclusions for `*.akamaiedge.net`, `*.cloudfront.net`.

### Ransomware File Burst Detector
- **Metric**: Sliding window rate of file modifications/creations with Shannon Entropy > 7.2 bits/byte.
- **Default Threshold**: > 20 high-entropy writes within a 10-second window.
- **Symptom**: Legitimate compression tools (tar, zip, 7z) or encrypted backup jobs triggering alerts.
- **Tuning**: Exclude known backup service paths or extend the window duration.

---

## 6. Plugin Diagnostics

### Plugin Lifecycle Failures
If a plugin fails to initialize or exits unexpectedly:
1. Verify the plugin version matches `1.0.0` (as defined in `internal/plugins/sdk.go`).
2. Review the plugin error log:
   ```
   r3trive plugins list --verbose
   ```
3. Check network reachability for external integration plugins (Splunk HEC, Elasticsearch, PagerDuty, Jira, VirusTotal, MISP).
4. Verify timeout boundaries: default plugin call execution timeout is 10 seconds.
