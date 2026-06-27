# R3TRIVE

> **Endpoint detection, threat hunting, and automated defense.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://golang.org/)
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
r3trive explain incident.json
r3trive summarize --last 24h
r3trive generate-rule --from incident.json
r3trive ask "What lateral movement techniques were used in INC-20240315-001?"
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

**From source:**
```bash
git clone https://github.com/thrive-spectrexq/r3trive
cd r3trive
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

Full architecture detail: [SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md)

---

## Technology Stack

| Layer | Technology |
|---|---|
| Primary language | Go 1.22+ |
| Performance-critical modules | Rust |
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

| Document | Description |
|---|---|
| [SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md) | Full component design and data flows |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat actors, attack surfaces, mitigations |
| [DETECTION_ENGINE_SPEC.md](docs/DETECTION_ENGINE_SPEC.md) | Behavioral detection internals |
| [PLUGIN_SDK.md](docs/PLUGIN_SDK.md) | Integration and plugin development |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | REST API and gRPC reference |
| [RULE_ENGINE_SPEC.md](docs/RULE_ENGINE_SPEC.md) | Rule language and authoring guide |
| [AI_ANALYST_SPEC.md](docs/AI_ANALYST_SPEC.md) | AI layer architecture and prompting |
| [DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | Full schema reference |
| [SOC_WORKFLOW.md](docs/SOC_WORKFLOW.md) | SOC integration and triage playbooks |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| Phase 1: MVP Core | ✅ Completed | CLI, ETW event collection, process/network monitoring, pipeline |
| Phase 2: Detection Platform | ✅ Completed | Behavioral correlation engine, YAML rules, YARA scanner mock |
| Phase 3: Response Platform | 📋 Planned | Automated containment, host isolation, quarantine |
| Phase 4: AI Platform | ✅ Completed | Local AI Analyst layer (Explain, Summarize, Generate, Ask) |
| Phase 5: Enterprise Platform | 📋 Planned | Fleet management, cloud dashboard, multi-tenant SOC |

---

## Security & Trust

R3TRIVE is built on zero-trust architecture principles:

- **Least privilege**: Every component operates with minimum required permissions
- **Continuous verification**: No implicit trust between subsystems
- **Immutable audit logs**: Tamper-evident event records
- **Signed releases**: All binaries are signed and verifiable

---

## Legal

R3TRIVE is intended exclusively for **defensive cybersecurity operations**, incident response, research, and authorized security assessments. Users are responsible for ensuring compliance with all applicable laws, regulations, and organizational policies. Unauthorized use against systems you do not own or have explicit permission to test is illegal and prohibited.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

---

## Community

- **GitHub Discussions**: [github.com/thrive-spectrexq/r3trive/discussions](https://github.com/thrive-spectrexq/r3trive/discussions)
- **Security Issues**: security@r3trive.io (PGP key in SECURITY.md)
- **Documentation**: [docs.r3trive.io](https://docs.r3trive.io)
