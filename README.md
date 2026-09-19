# R3TRIVE

> **Endpoint detection, threat hunting and automated defense.**

[![Version](https://img.shields.io/badge/version-v0.1.10-blue.svg)](https://github.com/thrive-spectrexq/r3trive/releases/tag/v0.1.10)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)]()
[![OpenTelemetry](https://img.shields.io/badge/telemetry-OpenTelemetry-blueviolet)]()

---

## What is R3TRIVE?

R3TRIVE is a cross-platform cybersecurity platform built for **defensive security operations at scale**. It combines behavioral endpoint detection, AI-assisted investigation, automated response, and threat hunting into a single terminal-first tool that runs anywhere — from a developer laptop to a 10,000-node enterprise fleet.

Where traditional security products rely on fragile signature databases and demand expensive infrastructure, R3TRIVE uses **behavioral analysis** correlated against MITRE ATT&CK, YARA, and Sigma rules to detect what signatures miss: fileless malware, living-off-the-land attacks, credential theft, and advanced persistent threats.

---

## Why R3TRIVE?

| Problem | R3TRIVE Solution |
|---|---|
| Alert fatigue from signature noise | Behavioral correlation reduces false positives |
| Fragmented tooling (EDR + SIEM + SOAR) | Unified detection, investigation, and response |
| Complex deployment | Single portable binary, zero dependencies |
| Analyst skill gap | AI Analyst Layer provides guided investigation |
| Slow manual response | Automated containment in seconds |

---

## Product Scope: Shipped MVP vs. Roadmap

To ensure operational predictability and deployment maturity, R3TRIVE clearly delineates between fully implemented production capabilities and planned roadmap modules:

### Shipped & Production-Ready (Current Release)
- **Core CLI & Runtime:** Single portable binary with deterministic operational exit codes (`0`-`5`), structured JSON/table output, and graceful OpenTelemetry shutdown flushing.
- **Config & Overlays:** Strict 4-tier precedence (`CLI Flags` > `Environment Variables` > `YAML Config` > `Defaults`) with schema and security validation.
- **Dual-Storage Engine:** SQLite embedded database for standalone single-host operations and PostgreSQL for centralized fleet telemetry aggregation.
- **Hardened API Server:** Built-in REST API with default loopback binding (`127.0.0.1:8080`), mandatory API key or TLS for non-loopback binds, token-bucket rate limiting, and CORS origin controls.
- **Threat Hunting & Inspection:** Live OS process enumeration (Windows Toolhelp32, Linux `/proc`, macOS `ps`), YARA/Sigma scanning, and host security baseline audits.
- **Defensive Response Foundation:** Process termination, network isolation, and file quarantine with dry-run support, path collision protection, and execution error reporting.

### Roadmap & Advanced Fleet Features (In Development)
- Continuous kernel-level real-time event streaming drivers (eBPF on Linux, ETW kernel driver on Windows).
- Distributed multi-broker event mesh (NATS JetStream / Apache Kafka) for 100,000+ host fleets.
- Bidirectional enterprise connectors for cloud SIEMs and automated SOAR orchestration.

---

## Operational Reference

### Standard CLI Exit Codes

Scripts and automation can rely on deterministic exit codes:

| Code | Status | Description |
|---|---|---|
| `0` | **Success** | Normal, successful command execution. |
| `1` | **Runtime Error** | Unexpected execution failure or unhandled exception. |
| `2` | **Configuration Error** | Invalid flags, YAML syntax error, or security validation failure. |
| `3` | **Permission Error** | Insufficient OS privileges (e.g., Administrator / root required). |
| `4` | **Storage Error** | Database connection, migration, or persistence failure. |
| `5` | **Platform Error** | Unsupported operating system or missing sensor kernel subsystem. |

### Configuration Precedence & Environment Overlays

Configuration is resolved in the following strict order of priority:
1. **CLI Flags** (`--log-level`, `--output`, etc.)
2. **Environment Variables** (`R3TRIVE_*`)
3. **YAML Configuration File** (`--config <path>` or platform default path)
4. **Compiled Defaults**

| Environment Variable | Config Equivalent | Default |
|---|---|---|
| `R3TRIVE_MODE` | `mode` | `development` (`production` supported) |
| `R3TRIVE_CONFIG` | (Path to config file) | System standard |
| `R3TRIVE_LOG_LEVEL` | `log_level` | `info` |
| `R3TRIVE_OUTPUT_FORMAT` | `output_format` | `table` |
| `R3TRIVE_DATA_DIR` | `data_dir` | Platform standard |
| `R3TRIVE_STORAGE_DRIVER` | `storage.driver` | `sqlite` (`postgres` supported) |
| `R3TRIVE_STORAGE_DSN` | `storage.dsn` | `<data_dir>/r3trive.db` |
| `R3TRIVE_STORAGE_BATCH_SIZE` | `storage.batch_size` | `100` |
| `R3TRIVE_API_ADDR` | `api.addr` | `127.0.0.1:8080` (loopback) |
| `R3TRIVE_API_KEY` | `api.api_key` | `""` |
| `R3TRIVE_API_TLS_CERT` | `api.tls_cert` | `""` |
| `R3TRIVE_API_TLS_KEY` | `api.tls_key` | `""` |
| `R3TRIVE_API_ALLOW_INSECURE_BINDING`| `api.allow_insecure_binding` | `false` |
| `R3TRIVE_TELEMETRY_ENABLED` | `telemetry.enabled` | `false` |
| `R3TRIVE_TELEMETRY_ENDPOINT` | `telemetry.endpoint` | `localhost:4317` |

> For production cluster operations, Kubernetes probes, and security hardening, see the [Operator's Guide](docs/OPERATOR_GUIDE.md).

---

## Features

### Endpoint Monitoring
Continuous behavioral monitoring of process creation, network activity, file modifications, registry changes, service creation, and scheduled tasks.

```bash
r3trive monitor
r3trive monitor --output json --level high
```

### Threat Hunting
Active hunting across host artifacts using YARA, Sigma, and custom behavioral rules.

```bash
r3trive hunt
r3trive hunt --technique T1003 --output report.json
```

### Incident Investigation
Deep analysis of suspicious binaries, processes, and activity with risk scoring.

```bash
r3trive investigate suspicious.exe
r3trive investigate --pid 4821
r3trive investigate --incident INC-20240315-001
```

Sample output:
```
═══════════════════════════════════════════
 R3TRIVE Incident Investigation Report
 Target: suspicious.exe
 Timestamp: 2024-03-15T14:32:01Z
═══════════════════════════════════════════

Risk Score: 94 / 100  ████████████████████ CRITICAL

Findings:
  [CRITICAL] Network beaconing to 185.220.101.47:443 (Tor exit node)
  [HIGH]     Registry persistence via HKCU\Run
  [HIGH]     Privilege escalation attempt (SeDebugPrivilege)
  [MEDIUM]   Packed/obfuscated binary (entropy 7.82)
  [MEDIUM]   Parent process spoofing detected

ATT&CK Techniques:
  T1071.001  Application Layer Protocol: Web Protocols
  T1547.001  Boot or Logon Autostart: Registry Run Keys
  T1055      Process Injection
  T1134      Access Token Manipulation

Recommended Action: IMMEDIATE ISOLATION
```

### Automated Defense
Trigger automated containment actions based on behavioral triggers or incident thresholds.

```bash
r3trive defend
r3trive defend --mode active --threshold 80
```

### Security Auditing
Host security baseline assessment.

```bash
r3trive audit
r3trive audit --profile cis-level2
r3trive audit --output audit-report.html
```

### AI Security Analyst
Natural-language incident explanation, rule generation, and attack chain reconstruction.

```bash
r3trive explain INC-20240315-001
r3trive summarize 24h
r3trive generate-rule "powershell spawned by office dumping lsass"
r3trive ask "What lateral movement techniques were used in INC-20240315-001?"
r3trive attack-chain INC-20240315-001
```

### YARA & Sigma Integration

```bash
r3trive yara scan sample.exe
r3trive yara scan --dir /tmp --recursive
r3trive sigma hunt
r3trive sigma hunt --ruleset /rules/custom/
```

---

## Quick Start

### Installation

**From binary (recommended):**
```bash
curl -sSL https://raw.githubusercontent.com/thrive-spectrexq/r3trive/main/install.sh | bash
```

**From source (via Makefile or Go CLI):**
```bash
git clone https://github.com/thrive-spectrexq/r3trive
cd r3trive

# Using Go CLI directly:
go build -o r3trive ./cmd/r3trive

# Or using Makefile:
make build
sudo make install
```

**Docker:**
```bash
docker run --privileged -v /:/host:ro thrive-spectrexq/r3trive monitor
```

### First Run

```bash
# Initialize configuration
r3trive init

# Run a quick security audit
r3trive audit --quick

# Start continuous monitoring
r3trive monitor

# Perform a threat hunt
r3trive hunt
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        R3TRIVE CLI                          │
│              (cobra + structured output layer)              │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Command Router                         │
└──────────┬──────────────────┬───────────────────┬───────────┘
           │                  │                   │
           ▼                  ▼                   ▼
┌──────────────┐   ┌─────────────────┐  ┌────────────────────┐
│ Detection    │   │  Response Core  │  │  Threat Engine     │
│ Core         │   │                 │  │                    │
│ • Process    │   │ • Kill process  │  │ • IOC matching     │
│ • File       │   │ • Block IP      │  │ • Reputation       │
│ • Network    │   │ • Quarantine    │  │ • Campaign ID      │
│ • Registry   │   │ • Isolate host  │  │ • YARA/Sigma       │
└──────┬───────┘   └────────┬────────┘  └────────┬───────────┘
       └──────────────────┬─┘                    │
                          ▼                      │
┌─────────────────────────────────────────────────────────────┐
│                    Correlation Engine                       │
│         (event stream → incident → ATT&CK mapping)          │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     AI Analyst Layer                        │
│   (local LLM / OpenAI-compatible / Ollama integration)      │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Plugin System                          │
│          (SIEM / EDR / Ticketing / Cloud / Feeds)           │
└─────────────────────────────────────────────────────────────┘
```

Full architecture detail: [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md) (or view online at [thrive-spectrexq.github.io/r3trive](https://thrive-spectrexq.github.io/r3trive/))

---

## Technology Stack

| Layer | Technology |
|---|---|
| Primary language | Go 1.22+ |
| Scripting / AI tooling | Python 3.11+ |
| Local storage | SQLite |
| Fleet/cluster storage | PostgreSQL |
| Telemetry | OpenTelemetry |
| Messaging | NATS (default), Kafka (enterprise) |
| AI | Ollama (local), OpenAI-compatible APIs |
| Rule formats | YARA, Sigma, custom R3TRIVE DSL |

---

## Detection Coverage

| Category | Coverage |
|---|---|
| MITRE ATT&CK Techniques | 200+ |
| Ransomware families | 40+ |
| Credential theft techniques | 25+ |
| Lateral movement patterns | 30+ |
| Persistence mechanisms | 50+ |
| Living-off-the-land binaries (LOLBins) | 150+ |

---

## Documentation

Full documentation is published to GitHub Pages: **[thrive-spectrexq.github.io/r3trive](https://thrive-spectrexq.github.io/r3trive/)**

| Document | Description |
|---|---|
| [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md) | Full component design and data flows |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat actors, attack surfaces, mitigations |
| [DETECTION_ENGINE_SPEC.md](DETECTION_ENGINE_SPEC.md) | Behavioral detection internals |
| [PLUGIN_SDK.md](PLUGIN_SDK.md) | Integration and plugin development |
| [API_REFERENCE.md](API_REFERENCE.md) | REST API and gRPC reference |
| [RULE_ENGINE_SPEC.md](RULE_ENGINE_SPEC.md) | Rule language and authoring guide |
| [AI_ANALYST_SPEC.md](AI_ANALYST_SPEC.md) | AI layer architecture and prompting |
| [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) | Full schema reference |
| [SOC_WORKFLOW.md](SOC_WORKFLOW.md) | SOC integration and triage playbooks |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |

---

## Legal

R3TRIVE is intended exclusively for **defensive cybersecurity operations**, incident response, research, and authorized security assessments. Users are responsible for ensuring compliance with all applicable laws, regulations, and organizational policies. Unauthorized use against systems you do not own or have explicit permission to test is illegal and prohibited.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
