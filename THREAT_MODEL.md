# THREAT_MODEL.md

**R3TRIVE Threat Model**
Version: 1.0.0
Status: Draft
Methodology: STRIDE + ATT&CK

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Assets](#2-system-assets)
3. [Trust Boundaries](#3-trust-boundaries)
4. [Threat Actors](#4-threat-actors)
5. [Attack Surface Analysis](#5-attack-surface-analysis)
6. [STRIDE Threat Analysis](#6-stride-threat-analysis)
7. [Mitigations](#7-mitigations)
8. [Residual Risk Register](#8-residual-risk-register)
9. [Detection Coverage for Threats R3TRIVE Detects](#9-detection-coverage-goals)

---

## 1. Overview

This document models threats against:
1. **R3TRIVE itself** — threats targeting the security tool to blind, disable, or subvert it
2. **Systems protected by R3TRIVE** — threat actor TTPs that R3TRIVE is designed to detect

Threat modeling follows STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) for the first category, and MITRE ATT&CK for the second.

### 1.1 Assumptions

- R3TRIVE runs on a potentially compromised host (adversary may already have foothold)
- Adversaries are aware security tooling exists and may attempt to disable it
- Network communication may traverse untrusted networks
- Plugins may be authored by third parties

### 1.2 Out of Scope

- Physical access attacks to the host hardware
- Supply chain attacks on the Go toolchain or standard library
- Vulnerabilities in the underlying OS kernel

---

## 2. System Assets

### 2.1 Critical Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Event Log | Tamper-evident record of all security events | Critical |
| Detection Rules | YARA, Sigma, and correlation rules | High |
| AI API Keys | Credentials for cloud AI backends | High |
| IOC Database | Threat intelligence IOC store | High |
| Agent Configuration | Detection thresholds, response policies | High |
| Incident Records | Historical incidents and investigations | High |
| Plugin Code | Third-party plugin binaries | Medium |
| Telemetry Data | Operational metrics and traces | Medium |

### 2.2 Asset Sensitivity Rationale

**Event Log** is critical because:
- Tampering with it could hide attacker activity
- It forms the basis for incident response decisions
- Legal and compliance value

**Detection Rules** are high sensitivity because:
- Revealing them helps attackers evade detection
- Modification enables stealthy bypass

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE                                                 │
│  ┌──────────────────────┐   ┌─────────────────────────────┐     │
│  │  Internet / External │   │  Monitored Host (untrusted) │     │
│  │  - AI API endpoints  │   │  - Running processes        │     │
│  │  - Threat feed URLs  │   │  - File system              │     │
│  │  - TAXII servers     │   │  - Network traffic          │     │
│  └──────────────────────┘   └─────────────────────────────┘     │
└───────────────────────────────────────────────────────────────T1┘
                               T1 = Trust Boundary 1
┌─────────────────────────────────────────────────────────────────┐
│  PARTIALLY TRUSTED ZONE                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  R3TRIVE Plugin Processes                                │   │
│  │  (gRPC over Unix socket, separate process, limited caps) │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────T2┘
                               T2 = Trust Boundary 2
┌─────────────────────────────────────────────────────────────────┐
│  TRUSTED ZONE                                                   │
│  ┌────────────────────┐    ┌─────────────────────────────────┐  │
│  │  R3TRIVE Core      │    │  Configuration / Keys           │  │
│  │  (Detection, AI,   │    │  (filesystem with DAC/MAC)      │  │
│  │   Response, Store) │    │                                 │  │
│  └────────────────────┘    └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Threat Actors

### 4.1 External Adversaries

**Nation-State APT Groups**
- Motivation: Espionage, disruption, intellectual property theft
- Capability: Very high (custom tooling, zero-days, supply chain attacks)
- Likelihood of targeting R3TRIVE: Medium (would attempt to blind security tooling)
- TTPs relevant to R3TRIVE evasion: LOLBAS, process hollowing, driver exploits to kill EDR

**Ransomware Operators**
- Motivation: Financial extortion
- Capability: High (organized groups with specialized tools)
- Likelihood of targeting R3TRIVE: High (ransomware routinely kills AV/EDR before detonation)
- TTPs: Service termination, driver exploits (BYOVD), safe mode reboot

**Commodity Malware / Script Kiddies**
- Motivation: Opportunistic
- Capability: Low to medium
- TTPs: Known exploits, commodity RATs, automated scanning

### 4.2 Insider Threats

**Malicious Insider (Admin)**
- Motivation: Financial, espionage, sabotage
- Capability: High (legitimate access to system)
- Risk: Can modify configuration, disable sensors, delete logs

**Negligent Insider**
- Motivation: None (accidental)
- Risk: Misconfiguration, accidental exposure of logs

### 4.3 Third-Party / Plugin Risk

Malicious or compromised plugin:
- Motivation: Supply chain attack
- Risk: Plugin has access to event stream, could exfiltrate or suppress events

---

## 5. Attack Surface Analysis

### 5.1 Attack Surface — R3TRIVE Binary

| Surface | Description | Exposure |
|---|---|---|
| CLI argument parsing | Malformed input to CLI | Local |
| Config file parsing | Malformed YAML/TOML | Local |
| YARA rule loading | Malformed YARA rules | Local |
| Sigma rule loading | Malformed Sigma YAML | Local |
| Plugin gRPC socket | Plugin communication | Local |
| REST API (if enabled) | HTTP endpoints | Network |
| AI API client | HTTP client to AI provider | Outbound |
| Threat feed client | HTTP client to feed URLs | Outbound |
| Storage layer | SQLite/PostgreSQL queries | Local/Network |
| Event parser | Malformed OS events | Kernel boundary |

### 5.2 Attack Surface — Agent Communication (Fleet Mode)

| Surface | Description | Exposure |
|---|---|---|
| NATS TLS connection | Agent to controller | Network |
| mTLS certificate handling | Certificate validation | Network |
| Event serialization | Protobuf deserialization | Network |
| Command channel | Commands from controller | Network |

---

## 6. STRIDE Threat Analysis

### 6.1 Spoofing

| ID | Threat | Component | Severity |
|---|---|---|---|
| S-001 | Attacker impersonates R3TRIVE controller to send false commands to agent | Agent ↔ Controller channel | Critical |
| S-002 | Malicious plugin claims false plugin identity | Plugin gRPC socket | High |
| S-003 | Attacker poisons threat feed to inject false IOCs | Threat feed ingestion | Medium |
| S-004 | Attacker creates fake R3TRIVE binary to replace legitimate one | Binary on disk | High |

**Mitigations for Spoofing:**
- S-001: mTLS mutual authentication on all agent-controller channels
- S-002: Plugin signing and manifest verification
- S-003: Feed source verification via HTTPS + HSTS; signature validation for STIX feeds
- S-004: Binary integrity verified via cosign signature on startup

### 6.2 Tampering

| ID | Threat | Component | Severity |
|---|---|---|---|
| T-001 | Attacker modifies event log to hide activity | Event Log | Critical |
| T-002 | Attacker modifies detection rules to create blind spots | Rule files | Critical |
| T-003 | Attacker modifies agent configuration to disable sensors | Config files | High |
| T-004 | Attacker modifies plugin binary to exfiltrate data | Plugin binaries | High |
| T-005 | Attacker patches R3TRIVE process memory to disable detection | Running process | High |
| T-006 | Attacker modifies AI prompts in transit (MITM) | AI API client | Medium |

**Mitigations for Tampering:**
- T-001: Cryptographic chain hash on event log; log verification command
- T-002: Rule file checksums verified on load and periodically; immutable rule mount in containers
- T-003: Config file checksum verified on load; config changes trigger alert
- T-004: Plugin manifest with hash of plugin binary; signature verification
- T-005: Anti-debug checks; process memory integrity monitoring (self-monitoring)
- T-006: TLS 1.3 with certificate pinning for AI API endpoints

### 6.3 Repudiation

| ID | Threat | Component | Severity |
|---|---|---|---|
| R-001 | Analyst disputes taking a response action | Response Core audit log | High |
| R-002 | Attacker denies a detected action occurred | Event Log | Medium |
| R-003 | Plugin denies sending malformed data | Plugin audit trail | Low |

**Mitigations for Repudiation:**
- R-001: All response actions logged with user identity, timestamp, and correlated incident ID
- R-002: Tamper-evident event log with chain hash
- R-003: All plugin IPC messages logged with message hash

### 6.4 Information Disclosure

| ID | Threat | Component | Severity |
|---|---|---|---|
| I-001 | Detection rules exposed to attacker (enables evasion) | Rule store | High |
| I-002 | AI API key exposed | Config / memory | High |
| I-003 | Incident data (PII, internal IPs) exfiltrated via plugin | Plugin | Medium |
| I-004 | Event stream sniffed in transit | Agent ↔ Controller | High |
| I-005 | Log files world-readable | Filesystem | Medium |

**Mitigations for Information Disclosure:**
- I-001: Rules stored with restricted file permissions; encrypted at rest option
- I-002: Secrets never written to disk; environment variable injection or keychain
- I-003: Plugin output filtered against data policy; plugin runs in restricted namespace
- I-004: mTLS encryption on all network communication
- I-005: Log files created with mode 0600; systemd journal integration on Linux

### 6.5 Denial of Service

| ID | Threat | Component | Severity |
|---|---|---|---|
| D-001 | Attacker floods event stream to exhaust memory | Ring buffer | High |
| D-002 | Malicious YARA rule with exponential backtracking | YARA scanner | Medium |
| D-003 | Attacker generates high-frequency file I/O to overwhelm file sensor | File sensor | Medium |
| D-004 | Plugin enters infinite loop and starves resources | Plugin process | Medium |
| D-005 | Storage disk full prevents event logging | Storage layer | High |
| D-006 | Ransomware kills R3TRIVE process before it can respond | Process | High |

**Mitigations for Denial of Service:**
- D-001: Ring buffer has hard size limit; backpressure to sensors on overflow
- D-002: YARA rule scanner has per-scan timeout (default 30s)
- D-003: Inotify/eBPF rate limiting per directory; event deduplication
- D-004: Plugin processes run in separate cgroup with resource limits
- D-005: Storage health monitoring; pre-emptive alerts at 80% capacity; circular log option
- D-006: R3TRIVE process protected via: systemd service restart policy, watchdog process, process name obfuscation option, kernel namespace protection (Linux)

### 6.6 Elevation of Privilege

| ID | Threat | Component | Severity |
|---|---|---|---|
| E-001 | Plugin escapes sandbox to gain core privileges | Plugin isolation | High |
| E-002 | Malformed event from sensor triggers code execution in core | Event parser | High |
| E-003 | SQL injection via malicious event data into SQLite | Storage layer | Medium |
| E-004 | Path traversal via malicious file path in event | File operations | Medium |
| E-005 | Attacker exploits buffer overflow in Rust FFI boundary | YARA/eBPF bindings | Medium |

**Mitigations for Elevation of Privilege:**
- E-001: Plugin runs in separate process with minimal capabilities; gRPC IPC boundary
- E-002: All event data validated and sanitized before processing; fuzzing of event parsers
- E-003: All database queries use prepared statements / ORM with parameterization
- E-004: All file paths validated with `filepath.Clean` and restricted to allowed directories
- E-005: Rust components use `#![forbid(unsafe_code)]` where possible; unsafe blocks audited

---

## 7. Mitigations

### 7.1 Control Summary

| Control Category | Controls |
|---|---|
| Authentication | mTLS for all network channels, API key for REST |
| Authorization | RBAC with least privilege roles |
| Integrity | Chain hash event log, config checksums, binary signing |
| Confidentiality | TLS 1.3 everywhere, secrets in memory only |
| Availability | Watchdog process, disk monitoring, rate limiting |
| Isolation | Plugin process separation, capability dropping |
| Auditing | Immutable audit log, all actions attributed |
| Resilience | Graceful degradation, component restart, event buffering |

### 7.2 Hardening Checklist

For production deployments:

- [ ] Run as dedicated non-root user (with only necessary capabilities)
- [ ] Enable plugin signature verification
- [ ] Configure disk usage alert threshold
- [ ] Enable mTLS on all inter-component channels
- [ ] Store AI API keys in keychain or secrets manager (never config file)
- [ ] Enable tamper-evident log verification (scheduled cron)
- [ ] Configure systemd watchdog for agent process
- [ ] Apply SELinux/AppArmor profile (provided in `/deployments/selinux/`)
- [ ] Restrict configuration file permissions to 0600
- [ ] Enable process protection mode (obfuscates process name from `ps`)

---

## 8. Residual Risk Register

After mitigations are applied, the following residual risks remain:

| ID | Risk | Likelihood | Impact | Residual Risk |
|---|---|---|---|---|
| RR-001 | Nation-state uses kernel zero-day to bypass all userspace sensors | Low | Critical | Medium |
| RR-002 | Ransomware with BYOVD kills R3TRIVE before watchdog can restart | Medium | High | Medium |
| RR-003 | Compromised plugin exfiltrates sanitized event data | Low | Medium | Low |
| RR-004 | AI API provider breached, exposing queries | Low | Medium | Low |
| RR-005 | Insider with admin role deletes event log | Low | High | Medium |

### Acceptance

Residual risks RR-001 through RR-005 are accepted with the following compensating controls:
- RR-001/RR-002: Offline backup of event log; secondary monitoring via network tap
- RR-004: Privacy-sensitive deployments use local Ollama instead of cloud AI
- RR-005: Event log replicated to remote immutable store (S3 with Object Lock)

---

## 9. Detection Coverage Goals

This section defines what TTPs R3TRIVE must detect to fulfill its defensive mission.

### 9.1 Priority 1 — Must Detect

| TTP | ATT&CK ID | Detection Method |
|---|---|---|
| Ransomware file encryption | T1486 | File sensor (mass rename + entropy), process behavior |
| LSASS credential dump | T1003.001 | Process sensor (LSASS access), ETW |
| Process injection | T1055 | Process sensor (remote thread creation) |
| Scheduled task persistence | T1053.005 | Service sensor, file sensor |
| Registry run key persistence | T1547.001 | Registry sensor |
| Reverse shell via common shells | T1059 | Network sensor (outbound from shell process) |
| Lateral movement via PsExec | T1021.002 | Process sensor, network sensor |
| Pass-the-hash / Pass-the-ticket | T1550 | Authentication log + network |
| Defense evasion: kill security tools | T1562.001 | Process sensor (termination of security products) |
| Data exfiltration over web | T1041 | Network sensor (large outbound transfer) |

### 9.2 Priority 2 — Should Detect

| TTP | ATT&CK ID | Detection Method |
|---|---|---|
| PowerShell obfuscation | T1027.010 | Process sensor (cmdline entropy) |
| WMI persistence | T1546.003 | Process sensor, WMI event subscription |
| DLL sideloading | T1574.002 | Process sensor (DLL load from unusual path) |
| Token impersonation | T1134 | Process sensor (privilege change) |
| Timestomping | T1070.006 | File sensor (MACE discrepancy) |
| DNS tunneling | T1071.004 | Network sensor (DNS query length/frequency) |
| Keylogging | T1056.001 | Process sensor (hook installation) |
| Screenshot capture | T1113 | Process sensor (GDI/screenshot API usage) |
| Browser credential theft | T1555.003 | File sensor (browser profile DB access) |

### 9.3 Priority 3 — Extended Coverage

| TTP | ATT&CK ID |
|---|---|
| Firmware persistence | T1542 |
| Bootkit | T1542.003 |
| Container escape | T1611 |
| Cloud credential theft | T1552.005 |
| Supply chain compromise indicators | T1195 |

---

*End of THREAT_MODEL.md*
*Related: SYSTEM_ARCHITECTURE.md, DETECTION_ENGINE_SPEC.md*
