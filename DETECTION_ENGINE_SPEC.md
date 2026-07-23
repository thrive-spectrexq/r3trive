# DETECTION_ENGINE_SPEC.md

**R3TRIVE Detection Engine Specification**
Version: 1.0.0
Status: Draft / Architectural Specification

> [!NOTE]
> **Implementation Status**: Windows ETW, Linux `/proc` polling, macOS process sensor, YARA scanning, Sigma transpiler, and IOC matching are implemented. eBPF kernel probes (Linux) and Endpoint Security Framework (macOS) are currently `[PLANNED]` / `[NOT YET IMPLEMENTED]`.

---

## Table of Contents

1. [Detection Philosophy](#1-detection-philosophy)
2. [Detection Layers](#2-detection-layers)
3. [Behavioral Detection Engine](#3-behavioral-detection-engine)
4. [Rule Evaluation Engine](#4-rule-evaluation-engine)
5. [YARA Integration](#5-yara-integration)
6. [Sigma Integration](#6-sigma-integration)
7. [IOC Matching Engine](#7-ioc-matching-engine)
8. [ML Anomaly Detection](#8-ml-anomaly-detection)
9. [Alert Lifecycle](#9-alert-lifecycle)
10. [False Positive Reduction](#10-false-positive-reduction)
11. [ATT&CK Mapping](#11-attck-mapping)
12. [Detection Rule Library](#12-detection-rule-library)

---

## 1. Detection Philosophy

### 1.1 Behavioral Over Signature

Signatures are brittle. A single byte change evades a signature-based rule. R3TRIVE's primary detection method is behavioral: what does this process **do**, not what does it **look like**.

The hierarchy of detection confidence:

```
High Confidence (behavioral)
  ├── Process creates child that establishes outbound connection
  ├── Process reads LSASS memory
  ├── Mass file rename with entropy increase (ransomware)
  └── Shell spawned by Office application

Medium Confidence (pattern)
  ├── Process name matches known tool (mimikatz)
  ├── Command line contains obfuscated PowerShell (-enc)
  └── Network connection to known-bad IP

Lower Confidence (static)
  ├── File hash matches known malware
  └── YARA signature match (known-good context)
```

### 1.2 Detection in Depth

Multiple independent detection methods should be able to catch the same attack. An adversary who evades behavioral detection may still be caught by IOC matching. One who changes hashes may still match a YARA rule.

### 1.3 Context Is Everything

An event is never evaluated in isolation. A PowerShell process is not suspicious. A PowerShell process spawned by Word, 3 seconds after a macro executed, connecting outbound to a Tor exit node, is very suspicious. Context window and event sequencing are fundamental to accurate detection.

---

## 2. Detection Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5: AI-Assisted Detection                                 │
│  (novel techniques, complex attack chains, analyst augmentation)│
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: ML Anomaly Detection                                  │
│  (statistical deviation from learned baseline)                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Correlation Rules                                     │
│  (multi-event temporal patterns → incidents)                    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Atomic Detection Rules                                │
│  (single-event behavioral rules → alerts)                       │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: IOC Matching                                          │
│  (hash, IP, domain, URL lookup against threat intel)            │
├─────────────────────────────────────────────────────────────────┤
│  Layer 0: YARA / Sigma                                          │
│  (static and log-based signature matching)                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Behavioral Detection Engine

### 3.1 Process Behavior Heuristics

The behavioral engine builds a model of expected process behavior:

#### Shell Spawned by Office Application

```
Trigger: process.create event
  parent.name ∈ {winword.exe, excel.exe, powerpnt.exe, outlook.exe, onenote.exe}
  child.name ∈ {cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, 
                regsvr32.exe, rundll32.exe, certutil.exe, bitsadmin.exe}
Severity: High
ATT&CK: T1059, T1566.001
```

#### LSASS Memory Read

```
Trigger: process.open_process event
  target.name == lsass.exe
  source.name ∉ {antivirus_whitelist, r3trive, svchost.exe}
  access_mask contains PROCESS_VM_READ
Severity: Critical
ATT&CK: T1003.001
```

#### Process Hollowing

```
Trigger: sequence within 10s
  1. process.create with suspended flag
  2. process.virtual_alloc in remote process
  3. process.create_remote_thread
Severity: Critical
ATT&CK: T1055.012
```

#### Ransomware Behavior

```
Trigger: within 30s window
  file.rename events > 50 where:
    entropy(new_content) > 7.5
    extension changed
  OR file.write events > 100 where:
    entropy(written_bytes) > 7.5
Severity: Critical
ATT&CK: T1486
```

#### Reverse Shell Indicators

```
Trigger: process.create
  name ∈ {bash, sh, zsh, cmd.exe, powershell.exe}
  parent.name ∈ {python, python3, nc, ncat, socat, perl, ruby, php}
  network.connect event within 5s from same PID
  network.remote_port ∈ {80, 443, 4444, 4445, 1337, 8080, 8443}
Severity: High
ATT&CK: T1059, T1071
```

#### Defense Evasion: Security Tool Kill

```
Trigger: process.terminate event
  target.name ∈ {security_products_list}  // maintained list of ~200 products
  source elevated privilege: true
Severity: High
ATT&CK: T1562.001
```

### 3.2 Network Behavior Heuristics

#### Beaconing Detection

Beaconing detection uses statistical analysis of connection intervals:

```
Algorithm:
1. Collect all outbound connections to same (ip, port) within 1-hour window
2. Calculate inter-connection intervals
3. Compute coefficient of variation (CV = stddev / mean)
4. If CV < 0.2 AND connection count > 5: beacon detected
   (low variation = regular interval = C2 beacon)

Severity: High
ATT&CK: T1071
```

#### DNS Tunneling

```
Triggers:
  dns.query events where:
    query_length > 50 characters
    subdomain depth > 4
    query_rate > 10/minute to same domain
    OR entropy(subdomain) > 3.5 (random-looking)

Severity: Medium
ATT&CK: T1071.004
```

#### Large Data Exfiltration

```
Trigger:
  network.send to external IP
  total_bytes_sent > 100MB within 1 hour
  AND no corresponding network.receive suggesting backup/sync
  AND hour_of_day outside normal business hours (configurable)

Severity: High
ATT&CK: T1041
```

### 3.3 File System Behavior Heuristics

#### Shadow Copy Deletion

```
Trigger: process.create
  cmdline matches:
    vssadmin.exe delete shadows
    wmic shadowcopy delete
    wbadmin delete catalog
    bcdedit /set recoveryenabled no

Severity: Critical
ATT&CK: T1490
```

#### Startup Folder Modification

```
Trigger: file.create OR file.modify
  path matches:
    C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*
    C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*
    ~/.config/autostart/*.desktop
    /etc/init.d/*, /etc/rc*.d/*
  written by unexpected process

Severity: High
ATT&CK: T1547.001
```

---

## 4. Rule Evaluation Engine

### 4.1 Rule Format

R3TRIVE uses a YAML-based rule format for atomic detection rules:

```yaml
# Rule Schema
id: string                    # Unique rule ID (e.g., R3T-001)
name: string                  # Human-readable rule name
description: string           # What this rule detects
version: semver               # Rule version
status: stable|experimental|deprecated
author: string
references:
  - url                       # CVE, blog post, etc.
tags:
  - string                    # e.g., "ransomware", "apt", "lolbas"

# Detection Logic
detection:
  type: atomic|sequence|aggregate
  
  # For atomic (single event):
  event:
    type: string              # event type (process.create, file.write, etc.)
    conditions:               # field match conditions
      field: value
      field:
        gte: value
        lte: value
        regex: pattern
        oneOf: [a, b, c]
        notOneOf: [a, b, c]
        contains: substring
  
  # For sequence (ordered events):
  sequence:
    - event: ...
    - event: ...
      within: duration        # relative to previous event
  
  # For aggregate (statistical):
  aggregate:
    event: ...
    count_gte: integer
    window: duration
    group_by: [field, ...]

# Filtering
filter:
  exclude:
    process.path: [list, of, trusted, paths]
  require:
    process.elevated: true

# Output
severity: low|medium|high|critical
confidence: 0.0-1.0

attack:
  tactic: string
  technique: string           # e.g., T1059.001
  subtechnique: string

response:
  auto_actions: []            # optional: trigger automated response
  notify: []                  # notification channels
```

### 4.2 Rule Evaluation Performance

Rules are compiled at startup into an optimized evaluation tree:

1. Rules are indexed by event type (O(1) lookup for candidate rules)
2. Within a type, conditions are evaluated short-circuit (fail fast)
3. Expensive operations (regex, entropy) evaluated last
4. Rules with `confidence < 0.5` and no ATT&CK technique are not evaluated in `--level high` mode

### 4.3 Rule Versioning

Rules are versioned and pinned. Updates via `r3trive rules update` pull from the signed R3TRIVE rule repository. Custom rules in `/rules/custom/` are never overwritten by updates.

---

## 5. YARA Integration

### 5.1 YARA Engine

R3TRIVE embeds a Go binding to the YARA C library (via cgo) for native performance. The YARA engine:

- Compiles all rules at startup into a single compiled ruleset
- Supports external variables for context injection (`filepath`, `filesize`, `filename`)
- Runs scans in isolated goroutines with timeout enforcement
- Memory-maps large files for efficient scanning

### 5.2 Scan Modes

| Mode | Command | Description |
|---|---|---|
| File scan | `r3trive yara scan <file>` | Scan a single file |
| Directory scan | `r3trive yara scan --dir <path>` | Recursive directory scan |
| Memory scan | `r3trive yara scan --pid <pid>` | Scan process memory |
| Stream scan | Internal (continuous) | Scan files as they're written |

### 5.3 Built-in YARA Rule Categories

| Category | Count | Description |
|---|---|---|
| Ransomware | 200+ | Known ransomware families |
| RAT | 150+ | Remote access trojans |
| Credential stealers | 100+ | Credential harvesting tools |
| Exploit kits | 80+ | Web exploit kit artifacts |
| Rootkits | 50+ | Kernel-level malware |
| Packers | 40+ | Known packer signatures |
| Webshells | 200+ | Web shell detection |
| LOLBAS abuse | 60+ | Living-off-the-land binary abuse patterns |

### 5.4 Custom YARA Rules

Place custom rules in `/rules/yara/custom/`. They are loaded alongside built-in rules. Naming convention: `<category>_<name>_<version>.yar`.

### 5.5 YARA Rule Timeout

Per-scan timeout is enforced to prevent regex catastrophe:

```yaml
# config.yaml
yara:
  scan_timeout: 30s          # timeout per file scan
  memory_scan_timeout: 60s   # timeout per process memory scan
  max_file_size: 100MB       # skip files larger than this
```

---

## 6. Sigma Integration

### 6.1 Sigma Transpiler

R3TRIVE includes a Sigma-to-native transpiler. Sigma rules are converted to R3TRIVE atomic detection rules at load time.

Supported Sigma backends:
- `windows` (ETW log sources)
- `linux` (syslog, auditd, eBPF)
- `macos` (ESF, unified log)

Unsupported Sigma features (graceful skip):
- `near` condition (approximated with temporal window)
- `count` on non-aggregatable fields

### 6.2 Sigma Rule Sources

Built-in Sigma rules sourced from:
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (core rule set, 3,000+ rules)
- R3TRIVE custom Sigma rules (100+ rules)

### 6.3 Sigma Conversion Report

When loading Sigma rules, a compatibility report is generated:

```
$ r3trive sigma validate --dir /rules/sigma/

Sigma Compatibility Report
==========================
Total rules: 3,247
Converted successfully: 2,891 (89%)
Partially converted: 298 (9%)
Failed to convert: 58 (2%)

Failed rules (excerpt):
  - win_rdp_reverse_tunnel.yml: 'near' condition not supported
  - linux_persistence_rc_local.yml: platform detection failed
  ...
```

---

## 7. IOC Matching Engine

### 7.1 IOC Store Design

The IOC store is optimized for high-throughput lookups during live event processing:

| IOC Type | Data Structure | Lookup Complexity |
|---|---|---|
| IP address | Radix tree (supports CIDR) | O(log n) |
| Domain | Suffix trie | O(k) where k=domain length |
| URL | Hash map (SHA256 of normalized URL) | O(1) |
| File hash (MD5/SHA1/SHA256) | Hash set | O(1) |
| Certificate thumbprint | Hash set | O(1) |
| User agent | Aho-Corasick automaton | O(n) where n=text length |

### 7.2 IOC Expiration

All IOCs carry a TTL. Expired IOCs are not used for matching but are retained for historical correlation.

Default TTLs by source:

| Source | Default TTL |
|---|---|
| Commercial threat feed | Per-feed (typically 90 days) |
| MISP | Per-event attribute |
| Manual IOC add | 365 days |
| AI-extracted | 30 days |

### 7.3 IOC Confidence Scoring

Not all IOCs are equal. Confidence scores affect the resulting alert severity:

| Confidence | Description | Alert Severity Modifier |
|---|---|---|
| 100 | Confirmed malicious (vetted by analyst) | +2 severity levels |
| 80 | High confidence (multiple sources) | +1 severity level |
| 60 | Medium confidence (single source) | No change |
| 40 | Low confidence (automated, unvetted) | -1 severity level |
| 20 | Informational (reputation feed) | Alert only if other indicators |

### 7.4 IOC Deconfliction

IOCs that match trusted/known-good IP ranges or domains are suppressed. Configurable allowlist:

```yaml
ioc_allowlist:
  ip_ranges:
    - 10.0.0.0/8       # RFC 1918
    - 172.16.0.0/12
    - 192.168.0.0/16
  domains:
    - "*.internal.corp"
    - "*.amazonaws.com"  # if using AWS
  hashes: []
```

---

## 8. ML Anomaly Detection

### 8.1 Baseline Learning Phase

On first deployment, R3TRIVE enters a 7-day learning phase to establish baseline behavior:

- Process creation frequency by time-of-day
- Network connection destinations by process
- File write patterns by directory
- User login times and source IPs
- Service start/stop frequency

Learning phase events still generate IOC and rule-based alerts but do not generate anomaly alerts.

### 8.2 Anomaly Detection Models

| Model | Algorithm | Feature Set |
|---|---|---|
| Process anomaly | Isolation Forest | CPU, memory, child count, network connections |
| Network anomaly | Statistical (Z-score) | Bytes sent/recv, connection count, destination entropy |
| User behavior | UEBA (LSTM optional) | Login time, source IP, access patterns |
| File access | Statistical | Files per minute, directory entropy, extension mix |

### 8.3 Anomaly Scoring

Anomaly scores are not reported as binary detections but as risk score contributions that feed into the correlation engine:

```
anomaly_contribution = anomaly_score × weight × recency_factor

Where:
  anomaly_score: 0.0–1.0 (model output)
  weight: configured per-model (default 0.3–0.7)
  recency_factor: 1.0 for last hour, 0.5 for last 24h, 0.1 for older
```

### 8.4 Model Updates

Models are retrained weekly on the retained event baseline. Retraining is resource-throttled (max 10% CPU). Models are persisted in binary format in the R3TRIVE data directory.

---

## 9. Alert Lifecycle

```
Detection (behavioral rule / IOC / YARA match)
    │
    ▼
Alert Created
    │  (id, type, severity, confidence, event_id, rule_id, timestamp)
    │
    ├──► Storage: written to alerts table
    │
    ├──► Correlation Engine: evaluated for incident grouping
    │
    ├──► Real-time output (if monitor mode active)
    │
    └──► Plugin notifications (if configured)

Correlation Engine Processing:
    │
    ├── Alert clusters with existing incident → Update incident
    │
    └── Alert starts new pattern → Create incident
    
Analyst Actions on Alert:
    ├── Acknowledge
    ├── Investigate (triggers deep investigation workflow)
    ├── False positive (suppresses rule + similar future alerts)
    ├── True positive (escalates incident priority)
    └── Close (marks resolved)
```

### 9.1 Alert States

| State | Description |
|---|---|
| `new` | Generated, not yet reviewed |
| `acknowledged` | Analyst has seen it |
| `investigating` | Under active investigation |
| `true_positive` | Confirmed malicious |
| `false_positive` | Confirmed benign, rule feedback submitted |
| `closed` | Resolved |

---

## 10. False Positive Reduction

### 10.1 Suppression Rules

When an alert is marked as false positive, a suppression rule is automatically generated:

```yaml
# Auto-generated suppression rule
id: SUPP-001
created: 2024-03-15T14:32:01Z
created_by: analyst@corp.com
original_rule: R3T-042
suppression_criteria:
  process.path: /usr/bin/myapp
  process.parent.path: /usr/sbin/cron
  network.remote_ip: 203.0.113.10
expires: 2024-06-15T14:32:01Z    # 90-day default
```

Suppression rules expire after 90 days and require revalidation.

### 10.2 Trusted Process Allowlist

A global allowlist of trusted process paths/hashes that reduces alert verbosity:

```yaml
trusted_processes:
  - path: /usr/bin/apt
    operations: [file.write, network.connect]
    condition: "parent.name == 'apt-get'"
  - hash_sha256: "abc123..."
    name: "Internal IT tool"
    comment: "Verified by security team 2024-01-15"
```

### 10.3 Contextual Suppression

The system automatically suppresses repeated identical alerts from the same process/host within a configurable window:

```yaml
alert_deduplication:
  window: 10m
  group_by: [rule_id, host_id, process.pid]
  max_per_window: 3
```

---

## 11. ATT&CK Mapping

Every alert and incident in R3TRIVE is mapped to MITRE ATT&CK.

### 11.1 Coverage Heatmap Generation

Generate a heatmap of detection coverage:

```bash
r3trive coverage --output heatmap.html
r3trive coverage --format navigator-json > navigator-layer.json
```

The JSON output is compatible with the MITRE ATT&CK Navigator.

### 11.2 Coverage Statistics (Target)

| ATT&CK Tactic | Target Coverage |
|---|---|
| Initial Access | 60% |
| Execution | 80% |
| Persistence | 75% |
| Privilege Escalation | 70% |
| Defense Evasion | 65% |
| Credential Access | 85% |
| Discovery | 50% |
| Lateral Movement | 70% |
| Collection | 60% |
| Command and Control | 80% |
| Exfiltration | 65% |
| Impact | 75% |

---

## 12. Detection Rule Library

### 12.1 Built-in Rule Counts (Target v1.0)

| Category | Behavioral | IOC | YARA | Sigma | Total |
|---|---|---|---|---|---|
| Process execution | 45 | — | 80 | 200 | 325 |
| Credential access | 25 | 50 | 100 | 150 | 325 |
| Persistence | 30 | — | 60 | 180 | 270 |
| Lateral movement | 20 | 100 | 40 | 120 | 280 |
| Defense evasion | 35 | — | 80 | 200 | 315 |
| Ransomware | 15 | 200 | 200 | 50 | 465 |
| C2 communication | 20 | 500 | 50 | 100 | 670 |
| Exfiltration | 15 | 100 | 30 | 80 | 225 |
| Discovery | 10 | — | 20 | 100 | 130 |
| **Total** | **215** | **950** | **660** | **1,180** | **3,005** |

### 12.2 Rule Update Cadence

| Rule Type | Update Frequency | Source |
|---|---|---|
| Behavioral | Monthly | R3TRIVE team |
| YARA | Weekly | Community + R3TRIVE |
| Sigma | Daily (auto-sync) | SigmaHQ |
| IOC | Daily / Real-time | Threat feed subscriptions |
| Suppression | Analyst-driven | Auto-generated from FP feedback |

---

*End of DETECTION_ENGINE_SPEC.md*
*Related: RULE_ENGINE_SPEC.md, SYSTEM_ARCHITECTURE.md, THREAT_MODEL.md*
