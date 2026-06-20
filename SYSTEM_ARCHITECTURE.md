# SYSTEM_ARCHITECTURE.md

**R3TRIVE System Architecture Specification**
Version: 1.0.0
Status: Draft
Last Updated: 2024-03-15

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Philosophy](#2-design-philosophy)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Component Deep Dives](#4-component-deep-dives)
   - 4.1 CLI Layer
   - 4.2 Command Router
   - 4.3 Detection Core
   - 4.4 Correlation Engine
   - 4.5 Response Core
   - 4.6 Threat Engine
   - 4.7 AI Analyst Layer
   - 4.8 Plugin System
   - 4.9 Storage Layer
   - 4.10 Telemetry Layer
5. [Data Flows](#5-data-flows)
6. [Deployment Models](#6-deployment-models)
7. [Security Architecture](#7-security-architecture)
8. [Performance Model](#8-performance-model)
9. [Failure Modes and Resilience](#9-failure-modes-and-resilience)
10. [Cross-Platform Considerations](#10-cross-platform-considerations)
11. [Scalability Architecture](#11-scalability-architecture)
12. [Integration Architecture](#12-integration-architecture)

---

## 1. Introduction

R3TRIVE is designed around the principle that security tooling should be **fast, portable, and composable**. This document describes every subsystem, the interfaces between them, and the design decisions that govern their behavior.

### 1.1 Scope

This document covers:
- All internal subsystems and their responsibilities
- Data flow between subsystems
- External interfaces (APIs, plugins, storage)
- Deployment topologies
- Security properties of the system itself

### 1.2 Non-Goals

This document does not cover:
- Implementation details of individual detection rules
- Specific ATT&CK technique mappings (see DETECTION_ENGINE_SPEC.md)
- User-facing command documentation (see API_REFERENCE.md)

### 1.3 Terminology

| Term | Definition |
|---|---|
| Event | A single observable action on a host (e.g., process creation) |
| Alert | A flagged event that matches a detection rule |
| Incident | A correlated group of alerts representing a threat campaign |
| Artifact | A file, binary, or registry entry of investigative interest |
| IOC | Indicator of Compromise |
| TTP | Tactic, Technique, and Procedure (MITRE ATT&CK terminology) |
| Agent | R3TRIVE running in continuous monitoring mode on a host |
| Controller | R3TRIVE running in fleet management mode |
| Sensor | A platform-specific module that collects raw OS events |

---

## 2. Design Philosophy

### 2.1 Separation of Concerns

Every subsystem has a single, well-defined responsibility. The Detection Core detects. The Correlation Engine correlates. The Response Core responds. They communicate through typed interfaces and never through shared mutable state.

### 2.2 Event Sourcing

All state in R3TRIVE is derived from an append-only event log. This gives us:
- Reproducible investigation replays
- Time-travel debugging
- Tamper evidence
- Audit compliance

### 2.3 Minimal Footprint

The agent must not be a target. It must:
- Use less than 2% CPU during steady-state monitoring
- Consume less than 150MB RAM
- Write minimal disk I/O (batch writes, configurable flush intervals)
- Not open unnecessary network ports in agent mode

### 2.4 Defense in Depth

R3TRIVE is itself hardened against attack. Process memory is locked where the OS permits. Configuration files are checksum-verified on load. Communication between components is mutually authenticated.

### 2.5 Graceful Degradation

If the AI layer is unavailable, detection continues. If the correlation engine is backlogged, events are queued. If storage is full, critical events take priority. No single component failure causes total loss of visibility.

---

## 3. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE LAYER                     │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────────┐   │
│  │  CLI (cobra)│  │  REST API   │  │  Web Dashboard (Ent.) │   │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬────────────┘   │
└─────────┼────────────────┼──────────────────────┼───────────────┘
          │                │                      │
          └────────────────┴──────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                        COMMAND ROUTER                            │
│                                                                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────┐  │
│  │  Auth/AuthZ│ │Rate Limiter│ │ Middleware  │ │ Output Fmt  │  │
│  └────────────┘ └────────────┘ └────────────┘ └─────────────┘  │
└──────────────────────────────┬───────────────────────────────────┘
                               │
         ┌─────────────────────┼──────────────────────┐
         │                     │                      │
         ▼                     ▼                      ▼
┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  DETECTION CORE │  │  RESPONSE CORE   │  │  THREAT ENGINE   │
│                 │  │                  │  │                  │
│  ┌───────────┐  │  │  ┌────────────┐  │  │  ┌────────────┐  │
│  │ Sensors   │  │  │  │  Playbooks │  │  │  │ YARA       │  │
│  ├───────────┤  │  │  ├────────────┤  │  │  ├────────────┤  │
│  │ Process   │  │  │  │  Actions   │  │  │  │ Sigma      │  │
│  │ File      │  │  │  │  - kill    │  │  │  ├────────────┤  │
│  │ Network   │  │  │  │  - block   │  │  │  │ IOC Feeds  │  │
│  │ Registry  │  │  │  │  - isolate │  │  │  ├────────────┤  │
│  │ Service   │  │  │  │  - quarant.│  │  │  │ Reputation │  │
│  └───────────┘  │  │  └────────────┘  │  │  └────────────┘  │
└────────┬────────┘  └────────┬─────────┘  └────────┬─────────┘
         │                    │                      │
         └────────────────────┴──────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                      CORRELATION ENGINE                          │
│                                                                  │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────────┐     │
│  │ Event Stream │  │ Rule Evaluator │  │ ATT&CK Mapper     │     │
│  ├──────────────┤  ├────────────────┤  ├───────────────────┤     │
│  │ Ring Buffer  │  │ Temporal Window│  │ Campaign Grouping │     │
│  └──────────────┘  └────────────────┘  └───────────────────┘     │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                       AI ANALYST LAYER                           │
│                                                                  │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────────┐     │
│  │ Prompt Engine│  │ Context Builder│  │  Model Router     │     │
│  ├──────────────┤  ├────────────────┤  ├───────────────────┤     │
│  │ RAG / KB     │  │ History Store  │  │ Ollama / OpenAI   │     │
│  └──────────────┘  └────────────────┘  └───────────────────┘     │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                        PLUGIN SYSTEM                             │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐     │
│  │   SIEM   │ │   EDR    │ │  Tickets │ │  Cloud / Custom  │     │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘     │
└──────────────────────────────┬───────────────────────────────────┘
                               │
               ┌───────────────┴────────────────┐
               ▼                                ▼
┌──────────────────────┐            ┌───────────────────────┐
│   STORAGE LAYER      │            │   TELEMETRY LAYER     │
│                      │            │                       │
│  SQLite (local)      │            │  OpenTelemetry        │
│  PostgreSQL (fleet)  │            │  Traces / Metrics     │
│  Event Log (append)  │            │  Logs                 │
└──────────────────────┘            └───────────────────────┘
```

---

## 4. Component Deep Dives

### 4.1 CLI Layer

The CLI is built on **cobra** with structured output support for human-readable and machine-readable (JSON, NDJSON, CSV) formats.

#### 4.1.1 Command Hierarchy

```
r3trive
├── init              # Initialize configuration
├── monitor           # Continuous endpoint monitoring
│   ├── --level       # alert level filter (low/medium/high/critical)
│   ├── --output      # output format
│   └── --daemon      # run as background daemon
├── hunt              # Threat hunting
│   ├── --technique   # target ATT&CK technique
│   ├── --ioc         # hunt for specific IOC
│   └── --ruleset     # custom rule directory
├── investigate       # Deep artifact investigation
│   ├── [file]        # investigate file
│   ├── --pid         # investigate running process
│   └── --incident    # re-investigate logged incident
├── audit             # Security baseline audit
│   ├── --profile     # audit profile (cis-level1, cis-level2, custom)
│   └── --output      # output format (json, html, pdf)
├── defend            # Automated defense
│   ├── --mode        # passive (alert only) / active (take action)
│   └── --threshold   # risk score threshold for auto-response
├── explain           # AI explanation of incident/alert
├── summarize         # AI summary of recent activity
├── generate-rule     # AI-generated detection rule from incident
├── ask               # Free-form AI security query
├── yara
│   ├── scan          # YARA scan file or directory
│   └── validate      # Validate YARA rule syntax
├── sigma
│   ├── hunt          # Hunt using Sigma rules
│   └── convert       # Convert Sigma to native format
├── plugin
│   ├── list          # List installed plugins
│   ├── install       # Install plugin
│   └── configure     # Configure plugin
└── config
    ├── show          # Show current configuration
    ├── set           # Set configuration value
    └── validate      # Validate configuration
```

#### 4.1.2 Output Formatting

All commands support `--output` flag with values:
- `table` (default, human-readable)
- `json` (structured, single object)
- `ndjson` (newline-delimited, for streaming)
- `csv` (for tabular data)
- `quiet` (exit code only, for scripts)

#### 4.1.3 Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success, no threats found |
| 1 | General error |
| 2 | Configuration error |
| 3 | Permission error |
| 10 | Threats detected (low) |
| 11 | Threats detected (medium) |
| 12 | Threats detected (high) |
| 13 | Threats detected (critical) |

---

### 4.2 Command Router

The Command Router is the internal dispatch layer between the CLI/API and the operational subsystems. It is not exposed directly to users.

#### 4.2.1 Responsibilities

- **Authentication**: Validate API keys and session tokens for API mode
- **Authorization**: Enforce RBAC policies on sensitive operations
- **Rate Limiting**: Prevent resource exhaustion from rapid command execution
- **Middleware Pipeline**: Logging, tracing, and metrics injection
- **Context Propagation**: Pass request context (user, session, correlation ID) downstream

#### 4.2.2 RBAC Roles

| Role | Permissions |
|---|---|
| `viewer` | monitor (read-only), summarize, explain |
| `analyst` | viewer + hunt, investigate, audit |
| `responder` | analyst + defend, quarantine, block |
| `admin` | responder + plugin management, config, user management |

---

### 4.3 Detection Core

The Detection Core is the most performance-critical component. It must collect OS-level events with minimal latency and overhead.

#### 4.3.1 Sensor Architecture

Sensors are platform-specific collection modules. Each sensor implements a common interface:

```go
type Sensor interface {
    Name() string
    Platform() []Platform
    Start(ctx context.Context, ch chan<- Event) error
    Stop() error
    Health() SensorHealth
}
```

##### Linux Sensors

| Sensor | Mechanism | Events |
|---|---|---|
| ProcessSensor | eBPF (kernel 5.8+) / fallback: /proc polling | exec, fork, exit |
| FileSensor | inotify / eBPF | create, modify, delete, rename |
| NetworkSensor | eBPF (tc hook) / pcap fallback | connect, listen, send, recv |
| RegistrySensor | N/A on Linux | — |
| ServiceSensor | systemd D-Bus / /proc/1 | start, stop, enable |

##### Windows Sensors

| Sensor | Mechanism | Events |
|---|---|---|
| ProcessSensor | ETW (Event Tracing for Windows) | exec, inject, exit |
| FileSensor | ETW / USN Journal | create, modify, delete, rename |
| NetworkSensor | ETW / WFP callbacks | connect, listen, send, recv |
| RegistrySensor | ETW RegNtSetValue callbacks | read, write, delete |
| ServiceSensor | Service Control Manager ETW | create, start, stop |

##### macOS Sensors

| Sensor | Mechanism | Events |
|---|---|---|
| ProcessSensor | Endpoint Security Framework | exec, fork, exit |
| FileSensor | Endpoint Security Framework | create, modify, delete |
| NetworkSensor | Network Extension / libpcap | connect, listen |
| RegistrySensor | N/A on macOS | — |
| ServiceSensor | launchd XPC / fs_usage | load, start, stop |

#### 4.3.2 Event Schema

Every event produced by any sensor conforms to this schema:

```json
{
  "id": "evt_01HN2X4Y5Z6A7B8C9D0E1F2G3H",
  "timestamp": "2024-03-15T14:32:01.000000000Z",
  "host": {
    "id": "host_abc123",
    "hostname": "WORKSTATION-01",
    "os": "linux",
    "os_version": "Ubuntu 22.04.3 LTS",
    "arch": "amd64",
    "tags": ["production", "finance"]
  },
  "type": "process.create",
  "severity": "medium",
  "sensor": "ProcessSensor",
  "data": {
    "pid": 12345,
    "ppid": 1001,
    "name": "cmd.exe",
    "path": "C:\\Windows\\System32\\cmd.exe",
    "cmdline": "cmd.exe /c powershell -enc <base64>",
    "user": "DOMAIN\\jsmith",
    "uid": 1001,
    "gid": 1001,
    "session_id": "3",
    "hashes": {
      "md5": "9b51a57b...",
      "sha256": "e3b0c44298fc..."
    },
    "parent": {
      "pid": 1001,
      "name": "explorer.exe",
      "path": "C:\\Windows\\explorer.exe"
    }
  },
  "enrichments": {},
  "raw": "<base64 encoded raw event if applicable>"
}
```

#### 4.3.3 Event Pipeline

```
OS Kernel
    │
    ▼ (eBPF hook / ETW / ESF)
Sensor (platform-specific)
    │
    ▼
Event Normalizer
    │  (maps platform-specific fields to common schema)
    ▼
Event Enricher
    │  (adds hashes, parent process, user info, geo-IP)
    ▼
Event Validator
    │  (schema validation, drop malformed events)
    ▼
Event Ring Buffer (in-memory, configurable size)
    │
    ├──► Real-time Detection Rules
    │
    ├──► Correlation Engine (async)
    │
    └──► Storage Layer (async, batched)
```

#### 4.3.4 eBPF Program Lifecycle (Linux)

R3TRIVE compiles eBPF programs at runtime using CO-RE (Compile Once, Run Everywhere) to support kernels 5.4+. The loading sequence is:

1. Detect kernel version and available BTF (BPF Type Format) data
2. Load pre-compiled eBPF object (embedded in binary via `//go:embed`)
3. Attach to tracepoints/kprobes via `cilium/ebpf`
4. Set up perf ring buffer for event delivery
5. Start userspace consumer goroutine

Fallback for kernels < 5.4: `/proc` polling with 100ms interval (higher overhead).

---

### 4.4 Correlation Engine

The Correlation Engine transforms raw event streams into meaningful security incidents.

#### 4.4.1 Processing Pipeline

```
Event Stream (from Detection Core)
    │
    ▼
Event Classifier
    │  (assigns event to category: process, network, file, etc.)
    ▼
Temporal Window Manager
    │  (sliding windows: 60s, 5m, 15m, 1h, 24h)
    ▼
Rule Evaluator
    │  (evaluates correlation rules against windowed events)
    ▼
Incident Factory
    │  (creates/updates incident records)
    ▼
ATT&CK Mapper
    │  (maps incidents to MITRE ATT&CK techniques)
    ▼
Risk Scorer
    │  (calculates composite risk score 0-100)
    ▼
Incident Store
```

#### 4.4.2 Correlation Rule Language

Correlation rules are defined in YAML and evaluated by the rule engine. See RULE_ENGINE_SPEC.md for full DSL specification.

Example correlation rule (PowerShell credential dump detection):

```yaml
id: COR-001
name: PowerShell Credential Dump Chain
description: Detects PowerShell spawned by Office followed by credential access
severity: critical
window: 5m
conditions:
  sequence:
    - event:
        type: process.create
        data.name: powershell.exe
        data.parent.name:
          oneOf: [winword.exe, excel.exe, outlook.exe]
    - event:
        type: process.create
        data.name:
          oneOf: [lsass.exe, mimikatz.exe, procdump.exe]
        data.parent.name: powershell.exe
        within: 2m
attack:
  tactic: CredentialAccess
  technique: T1003.001
response:
  auto_actions:
    - kill_process: "$.events[1].data.pid"
    - alert: critical
```

#### 4.4.3 Risk Scoring Model

Risk score = Σ(finding_weight × confidence) × campaign_multiplier × recency_decay

Where:
- `finding_weight` is the base severity weight (low=10, medium=25, high=50, critical=90)
- `confidence` is 0.0–1.0 based on detection method reliability
- `campaign_multiplier` is 1.0–2.0 based on correlation with other incidents
- `recency_decay` reduces score for older events (half-life = 24 hours)

---

### 4.5 Response Core

The Response Core executes containment and remediation actions.

#### 4.5.1 Action Types

| Action | Description | Reversible | Privilege Required |
|---|---|---|---|
| `kill_process` | Terminate process by PID | No | Elevated |
| `block_ip` | Add firewall rule to block IP | Yes | Elevated |
| `quarantine_file` | Move file to quarantine store | Yes | Elevated |
| `disable_account` | Disable user account | Yes | Admin |
| `isolate_host` | Block all network except C2 channel | Yes | Elevated |
| `kill_connection` | Terminate active network connection | No | Elevated |
| `disable_service` | Stop and disable service | Yes | Admin |
| `revoke_token` | Revoke auth tokens via plugin | Yes | Plugin-dependent |

#### 4.5.2 Playbook Engine

Responses can be automated through playbooks — ordered sequences of actions with conditions:

```yaml
id: PB-001
name: Ransomware Containment
trigger:
  incident_type: ransomware_behavior
  risk_score_gte: 85
steps:
  - name: Kill malicious process
    action: kill_process
    params:
      pid: "$.incident.primary_pid"
    on_failure: continue
  - name: Isolate host
    action: isolate_host
    params:
      host_id: "$.incident.host_id"
      preserve_channels: ["r3trive-c2"]
    on_failure: alert_admin
  - name: Quarantine dropped files
    action: quarantine_file
    params:
      paths: "$.incident.artifact_paths"
  - name: Create ticket
    action: plugin.ticketing.create
    params:
      title: "Ransomware on {{ $.incident.host.hostname }}"
      priority: P1
      body: "{{ $.incident | summarize }}"
```

#### 4.5.3 Dry-Run Mode

All response actions support `--dry-run` flag which logs what actions would be taken without executing them. This is the default in `passive` mode.

---

### 4.6 Threat Engine

The Threat Engine provides threat intelligence correlation and rule-based scanning.

#### 4.6.1 IOC Management

IOCs are ingested from:
- STIX/TAXII feeds
- MISP exports
- Manual input (`r3trive ioc add`)
- AI-extracted IOCs from incident analysis

IOC types supported:
- IP address (v4 and v6)
- Domain
- URL
- File hash (MD5, SHA1, SHA256, SHA512)
- Certificate thumbprint
- Email address
- User agent string
- Registry key

#### 4.6.2 YARA Integration

YARA rules are compiled at startup and maintained in a compiled rule set for O(1) lookup. The scanner supports:
- Multi-threaded scanning
- Memory scanning of running processes
- Recursive directory scanning
- Timeout per scan
- Metadata extraction for matched rules

#### 4.6.3 Sigma Integration

Sigma rules are converted to native R3TRIVE correlation rules at load time using a built-in Sigma transpiler. The conversion is lossy for platform-specific features; a compatibility report is generated.

---

### 4.7 AI Analyst Layer

The AI Analyst Layer provides natural-language security analysis. See AI_ANALYST_SPEC.md for full specification.

#### 4.7.1 Model Support

| Backend | Type | Use Case |
|---|---|---|
| Ollama | Local | Air-gapped, privacy-sensitive |
| OpenAI API | Cloud | Best quality, requires connectivity |
| Any OpenAI-compatible | Cloud/local | Flexibility |
| Anthropic API | Cloud | Optional integration |

#### 4.7.2 Context Window Management

Each AI request includes:
1. System prompt (security analyst persona)
2. Structured incident/event data (JSON)
3. Relevant ATT&CK context (from knowledge base)
4. Historical context (last N incidents)
5. User query

Total context is managed to fit within the model's context window, with priority ordering: user query > incident data > historical context.

---

### 4.8 Plugin System

Plugins extend R3TRIVE without modifying the core. See PLUGIN_SDK.md for full specification.

#### 4.8.1 Plugin Types

| Type | Purpose |
|---|---|
| `input` | Ingest events from external sources |
| `output` | Send alerts/incidents to external systems |
| `enrichment` | Add context to events |
| `action` | Add new response action types |
| `intelligence` | Add threat feed sources |

#### 4.8.2 Plugin Interface

Plugins communicate with the core via gRPC over a Unix domain socket (or TCP for remote plugins). This provides:
- Language independence (any gRPC-capable language)
- Process isolation (plugin crash doesn't crash core)
- Security boundary (plugins run with minimal privilege)

---

### 4.9 Storage Layer

#### 4.9.1 Storage Tiers

| Tier | Technology | Use Case | Retention Default |
|---|---|---|---|
| Hot | In-memory ring buffer | Real-time correlation | Last 10,000 events |
| Warm | SQLite | Local agent, single-host | 30 days |
| Cold | PostgreSQL | Fleet, multi-host | 1 year |
| Archive | S3/GCS/Azure Blob | Long-term compliance | Configurable |

#### 4.9.2 Write Path

All writes are asynchronous. Events flow from the ring buffer to SQLite in batches (default: 100 events or 1 second, whichever comes first). PostgreSQL sync occurs on a configurable schedule.

#### 4.9.3 Event Log Integrity

Each event record includes:
- Sequential event ID
- SHA256 hash of the event content
- Chain hash (SHA256 of previous chain hash + current event hash)
- Signature (when key management is configured)

This creates a tamper-evident chain that can be verified with `r3trive verify-log`.

See DATABASE_SCHEMA.md for complete schema.

---

### 4.10 Telemetry Layer

R3TRIVE emits OpenTelemetry signals for all major operations.

#### 4.10.1 Signals

**Traces**: Request-scoped traces for every command execution, covering all subsystem calls.

**Metrics**:

| Metric | Type | Description |
|---|---|---|
| `r3trive.events.total` | Counter | Total events processed |
| `r3trive.events.per_second` | Gauge | Current event processing rate |
| `r3trive.alerts.total` | Counter | Total alerts generated |
| `r3trive.incidents.active` | Gauge | Currently active incidents |
| `r3trive.detection.latency` | Histogram | Time from event to alert |
| `r3trive.correlation.latency` | Histogram | Time from alert to incident |
| `r3trive.ai.request.duration` | Histogram | AI API call duration |
| `r3trive.sensor.health` | Gauge | Per-sensor health score |

**Logs**: Structured JSON logs emitted to stderr or configurable sink. Log levels: trace, debug, info, warn, error.

---

## 5. Data Flows

### 5.1 Normal Monitoring Flow

```
1. OS generates kernel event (e.g., new process created)
2. Sensor (eBPF/ETW/ESF) receives event in kernel/user boundary
3. EventNormalizer maps to common schema
4. EventEnricher adds hash, parent, user info
5. Event written to ring buffer
6. Real-time rules evaluated against event (< 1ms target)
7. If rule match: Alert created, written to storage
8. Event forwarded to Correlation Engine queue
9. Correlation Engine evaluates temporal patterns
10. If correlation match: Incident created/updated
11. Incident forwarded to AI Analyst for async enrichment
12. If defense rules trigger: Response Core executes action
13. All events batched to SQLite / PostgreSQL
14. Telemetry emitted to configured exporter
```

### 5.2 Investigation Flow

```
1. User runs `r3trive investigate <target>`
2. Command Router validates request
3. Detection Core performs static analysis on artifact
4. Threat Engine checks IOC matches, YARA scan
5. Historical events queried from Storage for related activity
6. Correlation Engine identifies related incidents
7. AI Analyst Layer constructs investigation report
8. Risk score calculated
9. Report rendered to user in requested format
```

### 5.3 Automated Defense Flow

```
1. Incident risk score exceeds configured threshold
2. Playbook Engine selects matching playbook
3. Playbook steps evaluated in order
4. Response Core executes each action
5. Results logged to incident timeline
6. Notification sent via configured plugins
7. Rollback plan stored for manual review
```

---

## 6. Deployment Models

### 6.1 Standalone Agent

Single binary on a single host. Stores data locally in SQLite. No network communication required except for optional AI and threat feed updates.

```
┌─────────────────────────────────┐
│           Host Machine          │
│                                 │
│  ┌───────────────────────────┐  │
│  │  R3TRIVE (all components) │  │
│  │  SQLite local storage     │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

### 6.2 Agent + Controller

Multiple agents report to a centralized controller. Agents send events and receive configuration from the controller.

```
┌───────────┐  ┌───────────┐  ┌───────────┐
│  Agent 1  │  │  Agent 2  │  │  Agent N  │
└─────┬─────┘  └─────┬─────┘  └─────┬─────┘
      │               │               │
      └───────────────┴───────────────┘
                      │ (NATS / TLS)
                      ▼
             ┌─────────────────┐
             │   Controller    │
             │  PostgreSQL     │
             │  Fleet Mgmt     │
             │  Central AI     │
             └─────────────────┘
```

### 6.3 Cloud-Native

R3TRIVE agents run as DaemonSets in Kubernetes. Central components run as Deployments with HA PostgreSQL.

```
┌────────────────────────────────────────┐
│           Kubernetes Cluster           │
│                                        │
│  DaemonSet: r3trive-agent              │
│  (one pod per node)                    │
│                                        │
│  Deployment: r3trive-controller (HA)   │
│  Deployment: r3trive-ai (HA)           │
│  StatefulSet: PostgreSQL               │
│  StatefulSet: NATS cluster             │
└────────────────────────────────────────┘
```

### 6.4 Air-Gapped

For environments without internet access:
- All threat feeds cached locally
- Local Ollama instance for AI features
- No external calls
- Update packages delivered via signed archive

---

## 7. Security Architecture

### 7.1 Component Security

#### CLI Binary

- Compiled with `-trimpath` to remove build paths
- CGO disabled where possible for reduced attack surface
- Version information embedded via `ldflags` at build time
- Binary signing via `cosign`

#### Agent Process

- Drops capabilities after startup except those required for sensors
- Locks process memory (`mlock`) for sensitive data in memory
- Watchdog process monitors agent health and restarts on crash
- Agent process not accessible via standard process list in hardened mode (Linux namespace isolation)

#### Configuration

- Configuration files are checksum-verified on load
- Secrets never written to disk in plaintext
- Environment variable or keychain-based secret injection

### 7.2 Communication Security

All inter-component communication uses mTLS. Certificate rotation is automated.

| Channel | Protocol | Authentication |
|---|---|---|
| Agent → Controller | gRPC over TLS 1.3 | mTLS + API key |
| Plugin → Core | gRPC over Unix socket | Socket permissions |
| REST API clients | HTTPS TLS 1.3 | Bearer token / mTLS |
| AI API calls | HTTPS TLS 1.3 | API key (in memory) |

### 7.3 Anti-Tampering

R3TRIVE detects attempts to interfere with its own operation:
- Monitors its own process for injection attempts
- Detects debugger attachment
- Validates rule file checksums before loading
- Alerts on configuration modification during runtime

---

## 8. Performance Model

### 8.1 Resource Targets

| Resource | Idle | Active Monitoring | Threat Hunting |
|---|---|---|---|
| CPU | < 0.5% | < 2% | < 15% |
| RAM | < 50MB | < 150MB | < 500MB |
| Disk I/O | < 1 MB/s | < 5 MB/s | < 50 MB/s |
| Network | 0 | ~100 KB/s (telemetry) | Configurable |

### 8.2 Event Throughput

| Metric | Target |
|---|---|
| Events/second (ingest) | > 50,000 |
| Event-to-alert latency (p99) | < 10ms |
| Alert-to-incident latency (p99) | < 500ms |
| YARA scan throughput | > 500 MB/s |
| AI response latency (p50, local) | < 5s |
| AI response latency (p50, cloud) | < 2s |

### 8.3 Scaling Limits

| Configuration | Max Hosts | Max Events/Day |
|---|---|---|
| Standalone (SQLite) | 1 | 50M |
| Small fleet (PostgreSQL) | 100 | 5B |
| Enterprise (PostgreSQL + sharding) | 10,000+ | 500B+ |

---

## 9. Failure Modes and Resilience

### 9.1 Sensor Failure

If a sensor fails to start or crashes:
- Warning is logged and emitted as metric
- Other sensors continue operating
- Sensor restart attempted with exponential backoff (1s, 2s, 4s, 8s, max 60s)
- Health endpoint reports degraded status

### 9.2 Storage Failure

If storage is unavailable:
- Events buffered in memory ring buffer
- Buffer size configurable (default: 100,000 events)
- When buffer full: oldest events dropped, counter incremented
- Alert emitted on buffer > 80% capacity

### 9.3 AI Layer Failure

If AI backend is unavailable:
- All detection and response continues unaffected
- AI-dependent commands return graceful error
- Automatic retry with backoff on transient errors
- Fallback to cached analysis for known incident types

### 9.4 Correlation Engine Backlog

If correlation engine falls behind:
- Input queue depth monitored
- Automatic shedding of low-priority events (rate limited)
- High-severity events always processed
- Alert triggered when queue depth > 10,000 events

---

## 10. Cross-Platform Considerations

### 10.1 Build Matrix

| OS | Arch | Sensor Method | CGO Required |
|---|---|---|---|
| Linux | amd64 | eBPF (primary) | Yes (for eBPF loader) |
| Linux | arm64 | eBPF (primary) | Yes |
| Linux | 386 | /proc polling | No |
| Windows | amd64 | ETW | Yes (windows bindings) |
| Windows | arm64 | ETW | Yes |
| macOS | amd64 | Endpoint Security | Yes (ESF requires entitlement) |
| macOS | arm64 | Endpoint Security | Yes |

### 10.2 Platform-Specific Privilege Requirements

| Platform | Requirement | Why |
|---|---|---|
| Linux | `CAP_BPF`, `CAP_PERFMON` | eBPF program loading |
| Linux | `CAP_SYS_PTRACE` | Process inspection |
| Windows | Elevated (admin) | ETW session creation |
| macOS | Full Disk Access + Endpoint Security entitlement | ESF requires apple-signed entitlement or system extension |

### 10.3 Path Handling

All internal path handling uses `filepath.Join` and OS-native separators. No hardcoded `/` or `\` separators. Case-insensitivity handled per-platform for file and registry comparisons.

---

## 11. Scalability Architecture

### 11.1 Fleet Architecture

In fleet mode, a NATS JetStream cluster is used for reliable event delivery:

```
Agents (N) ──NATS publish──► JetStream cluster ──► Controller consumers
                                     │
                              ┌──────▼───────┐
                              │  Partitioned │
                              │  Streams     │
                              │  (by host)   │
                              └──────────────┘
```

NATS subject hierarchy:
```
r3trive.events.<host_id>.<event_type>
r3trive.alerts.<host_id>.<severity>
r3trive.incidents.<incident_id>
r3trive.commands.<host_id>
r3trive.responses.<host_id>
```

### 11.2 Horizontal Scaling

Controller components are stateless and can be horizontally scaled behind a load balancer. State lives in PostgreSQL. PostgreSQL uses read replicas for query scaling.

### 11.3 Database Partitioning

Events table is partitioned by:
1. Host ID (hash partitioning)
2. Timestamp (range partitioning, daily)

This enables efficient per-host queries and time-range scans with partition pruning.

---

## 12. Integration Architecture

### 12.1 SIEM Integration

R3TRIVE can forward events and incidents to SIEMs via:
- Syslog (RFC 3164 and RFC 5424)
- CEF (Common Event Format)
- LEEF (Log Event Extended Format)
- Elastic Common Schema (ECS) JSON
- OCSF (Open Cybersecurity Schema Framework)

### 12.2 SOAR Integration

Bidirectional integration with SOAR platforms:
- R3TRIVE can receive investigation commands from SOAR
- R3TRIVE sends incident data and evidence to SOAR
- Supported: Splunk SOAR, Palo Alto XSOAR, custom via webhooks

### 12.3 Ticketing Integration

Automatic ticket creation on incident detection. Supported platforms via plugins:
- ServiceNow
- Jira
- PagerDuty
- Opsgenie
- Custom webhook

### 12.4 Threat Intelligence Platforms

| Platform | Protocol | Direction |
|---|---|---|
| MISP | REST API | Bidirectional |
| OpenCTI | GraphQL API | Bidirectional |
| ThreatConnect | REST API | Read |
| VirusTotal | REST API | Read |
| TAXII 2.1 | HTTPS | Read |

---

*End of SYSTEM_ARCHITECTURE.md*
*Related: DETECTION_ENGINE_SPEC.md, PLUGIN_SDK.md, API_REFERENCE.md, DATABASE_SCHEMA.md*
