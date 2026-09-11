# RULE_ENGINE_SPEC.md

**R3TRIVE Rule Engine Specification**
Version: 1.0.0
Status: Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [Rule Types](#2-rule-types)
3. [Rule Format (Atomic Rules)](#3-rule-format-atomic-rules)
4. [Rule Format (Correlation Rules)](#4-rule-format-correlation-rules)
5. [Rule DSL Reference](#5-rule-dsl-reference)
6. [Event Field Reference](#6-event-field-reference)
7. [Rule Variables and Macros](#7-rule-variables-and-macros)
8. [Built-in Macros Reference](#8-built-in-macros-reference)
9. [Rule Testing](#9-rule-testing)
10. [Rule Authoring Guide](#10-rule-authoring-guide)
11. [Performance Considerations](#11-performance-considerations)

---

## 1. Overview

The R3TRIVE Rule Engine evaluates detection rules against the event stream in real time. It supports four rule formats:

1. **Atomic rules** — match a single event against conditions
2. **Correlation rules** — match patterns across multiple events over time
3. **Aggregate rules** — match statistical thresholds (count, frequency)
4. **Suppression rules** — reduce false positives by excluding known-good activity

All rules are authored in YAML. The engine processes rules in priority order and uses an optimized evaluation pipeline (see [Performance Considerations](#11-performance-considerations)).

---

## 2. Rule Types

| Type | Use Case | Examples |
|---|---|---|
| `atomic` | Single event matches a suspicious condition | PowerShell with encoded command, LSASS access |
| `sequence` | Ordered sequence of events within a time window | Office macro → PowerShell → network connection |
| `aggregate` | Count or frequency thresholds | > 50 file renames in 30 seconds (ransomware) |
| `suppression` | Exclude known-good activity | Backup process accessing many files |

---

## 3. Rule Format (Atomic Rules)

### 3.1 Schema

```yaml
# ─── Metadata ─────────────────────────────────────────────────────
id: string                          # R3T-{category}-{number}, e.g., R3T-EXEC-001
name: string
description: string
version: string                     # semver: "1.0.0"
status: stable | experimental | deprecated
author: string
created: date
modified: date
references:
  - https://...                     # relevant research, CVEs, blog posts

tags:
  - string                          # e.g., "powershell", "lolbas", "apt", "ransomware"

# ─── Detection Logic ──────────────────────────────────────────────
type: atomic

detection:
  event:
    type: string                    # event type (see Event Field Reference)
    
    # Field conditions (all conditions ANDed by default)
    conditions:
      field.path: value             # exact match
      field.path:
        eq: value                   # exact match (explicit)
        ne: value                   # not equal
        gt: number                  # greater than
        gte: number                 # greater than or equal
        lt: number                  # less than
        lte: number                 # less than or equal
        contains: substring         # string contains
        startsWith: prefix
        endsWith: suffix
        regex: pattern              # RE2 regex (NOT PCRE)
        oneOf: [a, b, c]            # value in list
        notOneOf: [a, b, c]         # value not in list
        exists: true | false        # field presence check
        
      # Entropy check (for detecting obfuscation)
      field.path:
        entropy_gte: 5.0            # Shannon entropy >= 5.0
        
      # Length check
      field.path:
        length_gte: 100
        length_lte: 1000
        
      # Cidr match (for IP fields)
      field.path:
        cidr: "10.0.0.0/8"         # matches IP in CIDR range
        notCidr: "192.168.0.0/16"
        
      # Logical operators
      any:                          # OR of child conditions
        - field: value
        - field: value
      all:                          # AND of child conditions (explicit)
        - field: value
      not:                          # NOT of child condition
        field: value

# ─── Filtering (reduce false positives) ───────────────────────────
filter:
  exclude:
    # Exclude events where these conditions match
    process.path:
      oneOf:
        - "C:\\Program Files\\BackupSolution\\backup.exe"
        - "/usr/bin/rsync"
    host.tags:
      contains: "honeypot"          # don't alert on honeypots
      
  require:
    # Only match events where these conditions are true
    process.elevated: true

# ─── Output ───────────────────────────────────────────────────────
severity: low | medium | high | critical
confidence: 0.0..1.0               # 0.0 = uncertain, 1.0 = certain

attack:
  tactic: string                   # MITRE tactic name
  technique: string                # e.g., "T1059.001"
  technique_name: string           # human-readable name

# ─── Response ─────────────────────────────────────────────────────
response:
  auto_actions: []                 # automated response actions (see Response Core)
  notify:
    - channel: slack
    - channel: pagerduty
      min_severity: high
```

### 3.2 Example Atomic Rules

**R3T-EXEC-001: PowerShell Encoded Command**

```yaml
id: R3T-EXEC-001
name: PowerShell Encoded Command
description: |
  Detects PowerShell execution with encoded command parameter (-enc/-EncodedCommand).
  Attackers commonly use base64 encoding to obfuscate malicious commands and evade
  command-line logging.
version: "1.2.0"
status: stable
author: R3TRIVE Team
tags: [powershell, obfuscation, lolbas]
references:
  - https://attack.mitre.org/techniques/T1027/010/

type: atomic

detection:
  event:
    type: process.create
    conditions:
      data.name:
        oneOf: [powershell.exe, pwsh.exe, powershell]
      data.cmdline:
        any:
          - contains: " -enc "
          - contains: " -EncodedCommand "
          - contains: " -ec "
          - regex: "-[eE][nN][cC]\\s+"

filter:
  exclude:
    data.parent.path:
      oneOf:
        - "C:\\Program Files\\Automation\\run.exe"   # internal automation tool

severity: medium
confidence: 0.7

attack:
  tactic: Defense Evasion
  technique: T1027.010
  technique_name: Obfuscated Files or Information: Command Obfuscation

response:
  notify:
    - channel: default
```

**R3T-CRED-001: LSASS Memory Access**

```yaml
id: R3T-CRED-001
name: LSASS Memory Read Detected
description: |
  Detects when a non-system process opens LSASS (Local Security Authority Subsystem
  Service) with read access to process memory. This is a primary technique for
  credential extraction tools like Mimikatz.
version: "1.0.0"
status: stable
author: R3TRIVE Team
tags: [credential-dumping, mimikatz, lsass]
references:
  - https://attack.mitre.org/techniques/T1003/001/

type: atomic

detection:
  event:
    type: process.open_process
    conditions:
      data.target.name: lsass.exe
      data.access_mask:
        any:
          - contains: PROCESS_VM_READ
          - contains: PROCESS_ALL_ACCESS
      data.source.name:
        notOneOf:
          - antivirus.exe
          - r3trive.exe
          - MsMpEng.exe
          - svchost.exe

severity: critical
confidence: 0.95

attack:
  tactic: Credential Access
  technique: T1003.001
  technique_name: OS Credential Dumping: LSASS Memory

response:
  auto_actions:
    - action: alert
      severity: critical
  notify:
    - channel: pagerduty
    - channel: slack
```

---

## 4. Rule Format (Correlation Rules)

### 4.1 Sequence Rules

Detect ordered sequences of events within a time window:

```yaml
id: R3T-COR-001
name: Office Macro Spawns Network-Connected Shell
description: |
  Detects a Microsoft Office application spawning a shell interpreter that 
  subsequently establishes an outbound network connection. This is a classic
  macro-based initial access and execution pattern.
version: "1.0.0"
status: stable
author: R3TRIVE Team

type: sequence

detection:
  window: 5m                       # all events must occur within 5 minutes
  ordered: true                    # events must occur in specified order
  
  sequence:
    - id: office_shell             # event alias for reference
      event:
        type: process.create
        conditions:
          data.parent.name:
            oneOf: [winword.exe, excel.exe, powerpnt.exe, outlook.exe]
          data.name:
            oneOf: [cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe]
    
    - id: network_connect
      event:
        type: network.connect
        conditions:
          data.pid: "{{office_shell.data.pid}}"   # same process as event 1
          data.remote_is_private: false             # outbound, not LAN
      within: 2m                   # within 2m of previous event

severity: critical
confidence: 0.9

attack:
  tactic: Execution
  technique: T1059
  technique_name: Command and Scripting Interpreter

response:
  auto_actions:
    - action: kill_process
      params:
        pid: "{{network_connect.data.pid}}"
  notify:
    - channel: pagerduty
```

### 4.2 Aggregate Rules

Detect statistical thresholds:

```yaml
id: R3T-IMPACT-001
name: Ransomware File Encryption Pattern
description: |
  Detects mass file rename/write operations with high entropy content,
  indicative of ransomware encryption behavior.
version: "1.0.0"
status: stable

type: aggregate

detection:
  window: 30s
  group_by: [host.id, data.process.pid]
  
  aggregate:
    - event:
        type: file.rename
        conditions:
          data.new_path:
            regex: "\\.[a-z0-9]{3,10}$"   # has extension
          data.entropy_delta_gte: 1.5       # entropy increased significantly
      count_gte: 50
    
    # OR: mass writes with high entropy
    OR:
    - event:
        type: file.write
        conditions:
          data.content_entropy_gte: 7.0
      count_gte: 100

severity: critical
confidence: 0.85

attack:
  tactic: Impact
  technique: T1486
  technique_name: Data Encrypted for Impact

response:
  auto_actions:
    - action: kill_process
      params:
        pid: "{{event.data.process.pid}}"
    - action: isolate_host
      params:
        preserve_channels: [r3trive-c2]
```

---

## 5. Rule DSL Reference

### 5.1 Condition Operators

| Operator | Type | Description | Example |
|---|---|---|---|
| `eq` | any | Equal to | `data.name: {eq: powershell.exe}` |
| `ne` | any | Not equal | `data.elevated: {ne: true}` |
| `gt` / `gte` | number | Greater than (or equal) | `data.size: {gte: 1048576}` |
| `lt` / `lte` | number | Less than (or equal) | `data.entropy: {lte: 3.0}` |
| `contains` | string | Substring match | `data.cmdline: {contains: "-enc"}` |
| `startsWith` | string | Prefix match | `data.path: {startsWith: "C:\\Temp"}` |
| `endsWith` | string | Suffix match | `data.path: {endsWith: ".exe"}` |
| `regex` | string | RE2 regex match | `data.cmdline: {regex: "-[eE][nN][cC]"}` |
| `oneOf` | list | Value in list | `data.name: {oneOf: [cmd.exe, powershell.exe]}` |
| `notOneOf` | list | Value not in list | `data.name: {notOneOf: [explorer.exe]}` |
| `exists` | bool | Field presence | `data.hash: {exists: true}` |
| `cidr` | IP string | IP in CIDR range | `data.remote_ip: {cidr: "10.0.0.0/8"}` |
| `notCidr` | IP string | IP not in range | `data.remote_ip: {notCidr: "192.168.0.0/16"}` |
| `entropy_gte` | float | Shannon entropy | `data.cmdline: {entropy_gte: 4.5}` |
| `length_gte` | int | String length | `data.cmdline: {length_gte: 200}` |
| `ioc_match` | bool | Matches IOC database | `data.remote_ip: {ioc_match: true}` |

### 5.2 Logical Operators

```yaml
conditions:
  # Implicit AND: all conditions at same level are ANDed
  data.name: powershell.exe
  data.elevated: true

  # Explicit OR
  any:
    - data.cmdline: {contains: "-enc"}
    - data.cmdline: {contains: "-EncodedCommand"}

  # Explicit AND (for nesting)
  all:
    - data.name: powershell.exe
    - data.elevated: true

  # NOT
  not:
    data.parent.name:
      oneOf: [wscript.exe, cscript.exe]
```

### 5.3 Cross-Event References (Sequence Rules)

In sequence rules, later events can reference fields from earlier events:

```yaml
sequence:
  - id: first_event
    event:
      type: process.create

  - id: second_event
    event:
      type: network.connect
      conditions:
        data.pid: "{{first_event.data.pid}}"      # same PID
        data.user: "{{first_event.data.user}}"    # same user
```

---

## 6. Event Field Reference

### 6.1 Common Fields (All Events)

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique event ID |
| `timestamp` | datetime | Event timestamp (nanosecond precision) |
| `type` | string | Event type (see below) |
| `severity` | string | Initial severity (low/medium/high/critical) |
| `host.id` | string | Host identifier |
| `host.hostname` | string | Hostname |
| `host.os` | string | Operating system (linux/windows/macos) |
| `host.tags` | []string | Host tags |

### 6.2 Process Events (`process.*`)

| Field | Type | Description |
|---|---|---|
| `data.pid` | int | Process ID |
| `data.ppid` | int | Parent process ID |
| `data.name` | string | Process name |
| `data.path` | string | Full executable path |
| `data.cmdline` | string | Full command line |
| `data.user` | string | User (DOMAIN\username on Windows) |
| `data.uid` | int | User ID (UNIX) |
| `data.gid` | int | Group ID (UNIX) |
| `data.elevated` | bool | Running with elevated privileges |
| `data.session_id` | string | Session/logon ID |
| `data.hash.md5` | string | MD5 of executable |
| `data.hash.sha256` | string | SHA256 of executable |
| `data.parent.pid` | int | Parent PID |
| `data.parent.name` | string | Parent process name |
| `data.parent.path` | string | Parent executable path |
| `data.flags.suspended` | bool | Process created in suspended state |

### 6.3 Network Events (`network.*`)

| Field | Type | Description |
|---|---|---|
| `data.pid` | int | Process ID |
| `data.process.name` | string | Process name |
| `data.local_ip` | string | Local IP address |
| `data.local_port` | int | Local port |
| `data.remote_ip` | string | Remote IP address |
| `data.remote_port` | int | Remote port |
| `data.protocol` | string | tcp/udp/icmp |
| `data.direction` | string | inbound/outbound |
| `data.remote_is_private` | bool | Remote IP in RFC 1918 range |
| `data.remote_hostname` | string | Resolved hostname (if available) |
| `data.bytes_sent` | int | Bytes sent |
| `data.bytes_recv` | int | Bytes received |
| `data.state` | string | Connection state |

### 6.4 File Events (`file.*`)

| Field | Type | Description |
|---|---|---|
| `data.path` | string | File path |
| `data.new_path` | string | New path (for renames) |
| `data.process.pid` | int | Writing process ID |
| `data.process.name` | string | Writing process name |
| `data.size` | int | File size in bytes |
| `data.hash.sha256` | string | SHA256 of file content |
| `data.entropy` | float | Shannon entropy of content |
| `data.extension` | string | File extension |
| `data.is_hidden` | bool | Hidden attribute |
| `data.is_system` | bool | System attribute |

### 6.5 Registry Events (`registry.*`) — Windows Only

| Field | Type | Description |
|---|---|---|
| `data.key` | string | Registry key path |
| `data.value_name` | string | Value name |
| `data.value_type` | string | REG_SZ/REG_DWORD/etc. |
| `data.value_data` | string | Value data (string representation) |
| `data.process.pid` | int | Process making the change |
| `data.process.name` | string | Process name |

---

## 7. Rule Variables and Macros

### 7.1 Built-in Variables

Available in condition values:

| Variable | Value |
|---|---|
| `$NOW` | Current timestamp |
| `$HOST_ID` | Current host ID |
| `$OS` | Current OS (linux/windows/macos) |

### 7.2 Macro System

Macros define reusable condition sets. Define in `/rules/macros/`:

```yaml
# macros/office_applications.yaml
id: MACRO_OFFICE_APPS
name: Microsoft Office Application Names
value:
  oneOf:
    - winword.exe
    - excel.exe
    - powerpnt.exe
    - outlook.exe
    - onenote.exe
    - mspub.exe
    - msaccess.exe
```

Use in rules:

```yaml
detection:
  event:
    conditions:
      data.parent.name:
        macro: MACRO_OFFICE_APPS
```

---

## 8. Built-in Macros Reference

| Macro ID | Description |
|---|---|
| `MACRO_OFFICE_APPS` | Microsoft Office executables |
| `MACRO_BROWSERS` | Common web browsers |
| `MACRO_SHELL_INTERPRETERS` | cmd.exe, powershell.exe, bash, sh, etc. |
| `MACRO_SCRIPT_ENGINES` | wscript.exe, cscript.exe, mshta.exe, etc. |
| `MACRO_LOLBAS` | 150+ Living-off-the-land binaries |
| `MACRO_SYSTEM_PATHS` | Trusted system binary directories |
| `MACRO_TEMP_PATHS` | Common temp/staging directories |
| `MACRO_KNOWN_TOOLS` | Known offensive security tools by name |
| `MACRO_PRIVATE_RANGES` | RFC 1918 IP ranges |
| `MACRO_WELL_KNOWN_PORTS` | Common service ports (22, 80, 443, etc.) |
| `MACRO_SUSPICIOUS_PORTS` | Common C2/RAT ports (4444, 1337, 8888, etc.) |
| `MACRO_CREDENTIAL_PROCESSES` | Processes that access credentials (LSASS, SAM) |
| `MACRO_PERSISTENCE_LOCATIONS` | Common persistence registry keys and paths |
| `MACRO_SECURITY_PRODUCTS` | ~200 known AV/EDR product names |

---

## 9. Rule Testing

### 9.1 Unit Testing Rules

```bash
# Test a single rule against a fixture event
r3trive rule test --rule R3T-EXEC-001 --event tests/fixtures/powershell_encoded.json

# Test all rules
r3trive rule test --all

# Test with verbose output
r3trive rule test --rule R3T-EXEC-001 --event tests/fixtures/powershell_encoded.json --verbose
```

### 9.2 Event Fixture Format

Test fixtures are JSON files matching the event schema:

```json
{
  "description": "PowerShell with encoded command spawned by Word",
  "expected_match": true,
  "expected_rule": "R3T-EXEC-001",
  "event": {
    "type": "process.create",
    "timestamp": "2024-03-15T14:32:01Z",
    "host": {
      "id": "test_host",
      "hostname": "TEST-MACHINE",
      "os": "windows"
    },
    "data": {
      "pid": 12345,
      "name": "powershell.exe",
      "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "cmdline": "powershell.exe -enc SQBFAFgA...",
      "elevated": false,
      "parent": {
        "pid": 1001,
        "name": "winword.exe",
        "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
      }
    }
  }
}
```

### 9.3 False Positive Testing

```bash
# Run rule against FP fixture (expected: no match)
r3trive rule test --rule R3T-EXEC-001 --event tests/fixtures/fp_admin_powershell.json

# Run full FP test suite
r3trive rule test --suite fp-suite --rule R3T-EXEC-001
```

### 9.4 Performance Testing

```bash
# Measure rule evaluation latency
r3trive rule bench --rule R3T-EXEC-001 --events 100000

# Output:
# Rule: R3T-EXEC-001
# Events evaluated: 100,000
# Duration: 1.23s
# Throughput: 81,300 events/sec
# p50 latency: 10μs
# p99 latency: 45μs
```

---

## 10. Rule Authoring Guide

### 10.1 Naming Conventions

| Element | Convention | Example |
|---|---|---|
| Rule ID | `R3T-{CATEGORY}-{NNN}` | `R3T-EXEC-001` |
| Custom Rule ID | `CUSTOM-{ORG}-{NNN}` | `CUSTOM-CORP-001` |
| Category codes | EXEC, CRED, PERS, PRIV, EVAD, DISC, LAT, COLL, C2, EXFIL, IMPACT, COR | — |

### 10.2 Writing High-Quality Rules

**Be specific, not broad.** A rule matching "any PowerShell" will fire thousands of times per day. A rule matching "PowerShell with encoded command, spawned by an Office app" fires rarely and accurately.

**Test for false positives first.** Before writing the detection logic, identify the legitimate activities that look similar and ensure the filter blocks them.

**Set confidence honestly.** A behavioral rule catching a highly specific pattern (like LSASS access with certain access masks) merits `confidence: 0.95`. A rule matching only a process name merits `confidence: 0.4`.

**Always include references.** Link to the relevant ATT&CK technique page, public research, or CVE. Rules without references are harder to maintain and trust.

**Use macros for common patterns.** Don't hardcode lists of Office applications or shell interpreters. Use `MACRO_OFFICE_APPS` etc.

### 10.3 Rule Lifecycle

```
Draft → Experimental → Stable → Deprecated → Removed

Draft:        Under development, not loaded by default
Experimental: Loaded in experimental mode, higher FP expected
Stable:       Production-ready, tuned FP rate
Deprecated:   Will be removed in next version, replacement exists
Removed:      Deleted from rule set
```

Transition from Experimental to Stable requires:
- 30-day observation period in production
- False positive rate < 5%
- At least 10 confirmed true positive hits documented

---

## 11. Performance Considerations

### 11.1 Rule Evaluation Pipeline

Rules are evaluated in an optimized pipeline:

1. **Event type index** — Rules are pre-indexed by event type. When a `process.create` event arrives, only rules with `event.type: process.create` are evaluated. O(1) lookup.

2. **Priority ordering** — Within a type, rules are evaluated in order of:
   - Severity (critical first)
   - Confidence (highest first)
   - Complexity (simplest first)

3. **Short-circuit evaluation** — Conditions are evaluated fail-fast. The most selective condition (lowest expected match rate) is evaluated first.

4. **Expensive operations last** — Regex and entropy calculations are placed last in the evaluation order. If cheaper conditions fail, expensive ones are skipped.

5. **Compiled rule cache** — Rules are compiled to an optimized in-memory representation at startup. YAML is only parsed once.

### 11.2 Avoiding Slow Rules

Slow patterns to avoid:

```yaml
# SLOW: regex without anchoring
data.cmdline:
  regex: "powershell"            # scans full string

# FAST: use contains + regex only when needed
data.cmdline:
  contains: "powershell"         # fast substring match

# SLOW: broad regex
data.cmdline:
  regex: ".*-.*-.*-.*"

# FAST: anchored, specific regex
data.cmdline:
  regex: "-enc\\s+[A-Za-z0-9+/=]{10,}"
```

### 11.3 Rule Complexity Budget

Rules are assigned a complexity score at compile time. Rules with score > 1000 are flagged and require explicit review:

| Operation | Complexity Score |
|---|---|
| Exact match | 1 |
| OneOf (10 items) | 5 |
| Contains | 3 |
| Regex (simple) | 20 |
| Regex (complex) | 50–200 |
| Entropy calculation | 100 |
| IOC lookup | 5 |
| Cross-event reference | 10 |

---

*End of RULE_ENGINE_SPEC.md*
*Related: DETECTION_ENGINE_SPEC.md, SYSTEM_ARCHITECTURE.md*
