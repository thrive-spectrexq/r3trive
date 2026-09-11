# SOC_WORKFLOW.md

**R3TRIVE SOC Workflow and Operations Guide**
Version: 1.0.0
Status: Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [SOC Integration Architecture](#2-soc-integration-architecture)
3. [Alert Triage Workflow](#3-alert-triage-workflow)
4. [Incident Response Workflow](#4-incident-response-workflow)
5. [Shift Handoff Procedures](#5-shift-handoff-procedures)
6. [Escalation Procedures](#6-escalation-procedures)
7. [Threat Hunting Workflow](#7-threat-hunting-workflow)
8. [Playbook Library](#8-playbook-library)
9. [Metrics and KPIs](#9-metrics-and-kpis)
10. [Role-Based Procedures](#10-role-based-procedures)
11. [Integration Guides](#11-integration-guides)

---

## 1. Overview

This document defines operational workflows for Security Operations Centers (SOCs) using R3TRIVE. It covers alert triage, incident response, threat hunting, escalation, and integration with common SOC tooling.

### 1.1 Intended Audience

- SOC Tier 1 Analysts (alert triage, initial investigation)
- SOC Tier 2 Analysts (deep investigation, threat hunting)
- Incident Responders (containment, eradication, recovery)
- SOC Managers (reporting, KPI tracking)
- Security Engineers (integration, tuning)

### 1.2 SOC Tier Model

| Tier | Role | R3TRIVE Permissions | Primary Activities |
|---|---|---|---|
| Tier 1 | Alert Analyst | `analyst` | Alert triage, initial classification, escalation |
| Tier 2 | Senior Analyst | `analyst` + hunting | Deep investigation, threat hunting, rule tuning |
| Tier 3 | IR Specialist | `responder` | Incident response, containment, forensics |
| Tier 4 | SOC Engineer | `admin` | Platform config, rule authoring, integration |

---

## 2. SOC Integration Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ENDPOINT FLEET                              │
│  Agent  Agent  Agent  Agent  Agent  Agent  ...  (N endpoints)       │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ Events (NATS/TLS)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      R3TRIVE CONTROLLER                             │
│  Detection  Correlation  AI Analyst  Response  Storage (PostgreSQL) │
└──────┬──────────────┬────────────────────────────────┬──────────────┘
       │              │                                │
       ▼              ▼                                ▼
┌──────────┐  ┌───────────────┐              ┌────────────────┐
│   SIEM   │  │ Ticketing     │              │  SOC Dashboard │
│ (Splunk/ │  │ (Jira/SN/PD)  │              │  (Web UI)      │
│  Elastic)│  └───────────────┘              └────────────────┘
└──────────┘         │
       │              ▼
       │    ┌───────────────┐
       │    │   SOAR        │
       │    │ (xSOAR/Splunk)│
       │    └───────────────┘
       │
       ▼
┌──────────────────────────────┐
│   Long-term Retention (S3)   │
└──────────────────────────────┘
```

---

## 3. Alert Triage Workflow

### 3.1 Overview

The triage workflow is the primary activity for Tier 1 analysts. The goal is to classify every alert as true positive, false positive, or needs escalation within the defined SLA.

### 3.2 SLA Targets

| Alert Severity | Initial Review SLA | Escalation Decision SLA |
|---|---|---|
| Critical | 15 minutes | 30 minutes |
| High | 1 hour | 2 hours |
| Medium | 4 hours | 8 hours |
| Low | 24 hours | 48 hours |

### 3.3 Triage Flowchart

```
New Alert Received
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│  Step 1: Initial Assessment (5 min for Critical, 15 min others)   │
│                                                                   │
│  Review:                                                          │
│  • What type of alert is it? (rule name + ATT&CK technique)       │
│  • Which host? What is the host's criticality?                    │
│  • What is the current risk score?                                │
│  • Are there related alerts or an existing incident?              │
└───────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│  Step 2: Context Gathering                                        │
│                                                                   │
│  r3trive explain <alert_id>        # AI-assisted context          │
│  r3trive investigate --pid <pid>   # if process-related           │
│                                                                   │
│  Check:                                                           │
│  • Is this host expected to perform this activity?                │
│  • Is this user expected to perform this activity?                │
│  • Is there a change ticket covering this activity?               │
│  • Has this rule fired on this host before? (false positive hist) │
└───────────────────────────────────────────────────────────────────┘
    │
    ├──────────────────────────────────────┐
    ▼                                      ▼
Known False Positive?                  Confirmed or Suspected TP?
    │                                      │
    ▼                                      ▼
Mark as False Positive              Acknowledge Alert
Create/update suppression           Escalate to Tier 2
rule if recurring                   Open Incident if not exists
Document in notes                   Set priority based on severity
    │                                      │
    ▼                                      ▼
Closed ────────────────────────────► Incident Response Workflow
```

### 3.4 False Positive Handling

When an alert is confirmed as a false positive:

```bash
# Mark alert as FP with suppression rule creation
r3trive alert update <alert_id> \
  --status false_positive \
  --note "Backup job accesses many files nightly - scheduled task BACKUP-001" \
  --create-suppression \
  --suppression-expires 90d
```

**Required documentation for false positive records:**

1. Why this is a false positive (specific justification, not just "expected behavior")
2. What legitimate activity caused the alert
3. Any supporting evidence (change ticket, approved process documentation)
4. Whether a suppression rule was created and when it expires

### 3.5 Alert Queue Management

```bash
# View current alert queue (sorted by severity + age)
r3trive alerts list --status new --sort severity:desc,created_at:asc

# Claim an alert for investigation
r3trive alert update <alert_id> --status acknowledged --assignee me

# Bulk acknowledge low-priority alerts during noise periods
r3trive alerts bulk-update \
  --filter "severity=low,rule_id=R3T-DISC-*,host_tag=dev" \
  --status acknowledged \
  --note "Dev environment discovery noise during deployment window"
```

---

## 4. Incident Response Workflow

### 4.1 Incident Lifecycle States

```
OPEN → INVESTIGATING → CONTAINED → ERADICATED → RECOVERED → CLOSED
                           │
                           └──► FALSE_POSITIVE (if misclassified)
```

### 4.2 P1/P2 Incident Response (Critical / High)

#### Immediately (0–15 min)

**Tier 1 Actions:**
```bash
# 1. Confirm alert is a true positive
r3trive explain <incident_id>

# 2. Escalate immediately to Tier 2 and IR
r3trive incident update <incident_id> \
  --priority P1 \
  --assignee <tier2_oncall> \
  --status investigating \
  --note "Escalated to IR team. Initial assessment: credential dumping active."
```

**Notification:**
- Page Tier 2 on-call via PagerDuty
- Notify SOC Manager
- Open Slack incident channel `#inc-<YYYYMMDD>-<ID>`
- (P1 only) Notify CISO

#### Investigation (15 min – 2 hr)

**Tier 2 Actions:**

```bash
# Reconstruct the attack chain
r3trive attack-chain <incident_id>

# Identify scope — what else was affected?
r3trive hunt \
  --ioc "185.220.101.47" \
  --ioc "invoice.docm" \
  --since "2h ago"

# Collect forensic evidence before containment
r3trive investigate <incident_id> --collect-evidence

# AI-assisted analysis
r3trive ask "What was the attacker's likely objective based on INC-20240315-001?" \
  --incident <incident_id>
```

**Determine scope:**
- Which hosts are affected?
- Which accounts are compromised?
- What data may have been accessed or exfiltrated?
- Is the attacker still active (live incident)?

#### Containment

**Tier 3 / Responder Actions:**

```bash
# Isolate affected host (blocks all network except R3TRIVE C2 channel)
r3trive respond --action isolate_host --host <host_id> --incident <incident_id>

# Kill malicious processes
r3trive respond --action kill_process --pid <pid> --host <host_id>

# Block C2 IP across all endpoints
r3trive respond --action block_ip --ip 185.220.101.47 --scope fleet

# Disable compromised account
r3trive respond --action disable_account --user "DOMAIN\\jsmith"

# Reset all active sessions (via plugin)
r3trive respond --plugin-action ad.force_logoff --user "DOMAIN\\jsmith"
```

Update incident status:
```bash
r3trive incident update <incident_id> \
  --status contained \
  --note "Host isolated at $(date). C2 IP blocked fleet-wide. Account disabled."
```

#### Eradication

Manual steps (outside R3TRIVE scope):
- Rebuild or reimage affected systems
- Remove malware artifacts and persistence mechanisms
- Patch exploited vulnerabilities
- Rotate credentials

```bash
# Verify eradication
r3trive hunt --host <host_id> --ruleset post-incident --since <containment_time>

# Document eradication
r3trive incident update <incident_id> --status eradicated \
  --note "Host reimaged. Persistence removed (registry key + scheduled task). Patch applied."
```

#### Recovery and Closure

```bash
# Verify clean before returning to production
r3trive audit --host <host_id> --profile post-incident

# Close incident with full documentation
r3trive incident close <incident_id> \
  --root-cause "Phishing email delivered malicious macro via invoice.docm" \
  --impact "Credentials for jsmith compromised; no confirmed lateral movement" \
  --note "Lessons learned: patch Office macro policy, implement FIDO2 MFA"
```

---

## 5. Shift Handoff Procedures

### 5.1 End-of-Shift Checklist

Every outgoing analyst must complete before shift end:

**Alert Queue:**
- [ ] All `Critical` and `High` alerts triaged
- [ ] All personally assigned alerts updated with current status and notes
- [ ] No alerts in `acknowledged` state for more than 2x SLA time without escalation

**Incident Updates:**
- [ ] All active incidents have been updated within the last 4 hours
- [ ] Any P1/P2 incidents have current Slack thread summarizing status

**Generate Shift Summary:**
```bash
r3trive summarize --since "8h ago" --format shift-handoff
```

**Template for shift handoff note:**
```
SHIFT HANDOFF — [DATE] [TIME] → [TIME]

OVERALL THREAT LEVEL: [LOW/MEDIUM/HIGH/CRITICAL]

ACTIVE INCIDENTS:
- INC-20240315-001 [P1/INVESTIGATING] — Credential theft on WORKSTATION-01
  Status: Host isolated. Awaiting reimage approval from IT.
  Next action: Validate clean before returning to network (assigned: incoming analyst)

ALERTS REQUIRING FOLLOW-UP:
- ALT-001 [HIGH/ACKNOWLEDGED] — Suspicious PowerShell on SERVER-02
  Context: No parent process data available. Needs Tier 2 review.

SUPPRESSION RULES CREATED:
- SUPP-042: Backup job on BACKUP-SRV suppressed for R3T-IMPACT-001 (90 days)

NOTES FOR INCOMING:
- BACKUP-SRV has scheduled maintenance window 02:00–04:00, expect elevated file activity alerts
```

---

## 6. Escalation Procedures

### 6.1 Escalation Matrix

| Situation | Escalate To | Channel | Timeframe |
|---|---|---|---|
| Critical alert | Tier 2 on-call | PagerDuty | Immediate |
| Suspected active breach | IR lead + CISO | Phone + Slack | Immediate |
| Ransomware indicators | IR lead + IT leadership | Phone | Immediate |
| Data exfiltration | IR lead + Legal + CISO | Phone | Immediate |
| Persistent threat actor | Tier 2 + Threat Intel | Slack | Within 30 min |
| Alert volume spike (>200% baseline) | SOC Manager | Slack | Within 15 min |
| Platform health issue | SOC Engineer | Slack | Within 15 min |

### 6.2 Escalation Template

When escalating to IR:

```
ESCALATION NOTICE — [DATE TIME]

Escalating: [YOUR NAME / TIER 1]
To: [ESCALATION TARGET]
Incident: [INC ID or "No incident yet"]
Severity: [P1/P2/P3]

SUMMARY:
[1-3 sentence description of what happened]

INDICATORS OBSERVED:
- [List key events/alerts]

AFFECTED SCOPE:
- Hosts: [list]
- Users: [list]
- Systems: [list]

ACTIONS TAKEN SO FAR:
- [list]

RECOMMENDED IMMEDIATE ACTIONS:
- [list]

DATA LINKS:
- Incident: https://r3trive.corp.com/incidents/[INC-ID]
- Slack channel: #inc-[ID]
```

---

## 7. Threat Hunting Workflow

### 7.1 Hunt Types

| Hunt Type | Trigger | Frequency |
|---|---|---|
| **Hypothesis-driven** | Threat intel, new CVE, industry reports | As needed |
| **IoC-driven** | New IOC received from feed or sharing | Within 24h |
| **Technique-driven** | ATT&CK technique not well-covered by detection | Weekly |
| **Baseline deviation** | Anomaly score spike on host or user | As triggered |
| **Post-incident** | After resolving an incident | After each incident |
| **Scheduled** | Routine sweep of high-value targets | Weekly |

### 7.2 Hunt Workflow

#### 1. Define the Hypothesis

Document the hunt objective before starting:
```
HUNT: APT29-style credential theft via LSASS
HYPOTHESIS: Threat actor has LSASS access going undetected via signed tool
TECHNIQUE: T1003.001
DATA SOURCE: Process events (last 72h)
SCOPE: All Domain Controllers + Finance workstations
```

#### 2. Execute the Hunt

```bash
# Hunt by ATT&CK technique across fleet
r3trive hunt \
  --technique T1003.001 \
  --scope "tag:domain-controller,tag:finance" \
  --since 72h

# Hunt for specific IOC
r3trive hunt --ioc "domain:evil.example.com" --since 30d

# Hunt with custom Sigma rule
r3trive sigma hunt \
  --rule /rules/custom/apt29_lsass.yml \
  --since 72h

# Free-form hunt with YARA
r3trive yara scan \
  --dir "C:\\Windows\\Temp" \
  --scope "tag:domain-controller" \
  --recursive
```

#### 3. Analyze Results

```bash
# Get AI analysis of hunt results
r3trive explain --hunt-id <hunt_id>

# Ask targeted question about results
r3trive ask "Were any signed binaries used for LSASS access in this hunt?" \
  --hunt <hunt_id>
```

#### 4. Document Hunt

Every hunt must be documented with:
- Hypothesis tested
- Data sources queried
- Time range covered
- Scope (hosts, users, tags)
- Results (positive findings or confirmed negative)
- New rules created (if any)
- False positives identified

```bash
r3trive hunt report --hunt-id <hunt_id> --output hunt_report.md
```

### 7.3 Hunt Packages

Pre-built hunt packages for common scenarios:

| Package | Targets | Description |
|---|---|---|
| `credential-theft` | All Windows hosts | LSASS access, SAM hive access, credential tool artifacts |
| `persistence` | All hosts | Scheduled tasks, registry run keys, startup folders, services |
| `lateral-movement` | Servers | PsExec, WMI, RDP, pass-the-hash indicators |
| `ransomware-prep` | All hosts | Shadow copy deletion, backup disruption, recovery disable |
| `c2-communication` | All hosts | Beaconing, DNS tunneling, unusual outbound protocols |
| `insider-threat` | All hosts | Data staging, bulk file access, cloud upload, USB write |

```bash
r3trive hunt --package credential-theft --since 7d
```

---

## 8. Playbook Library

### 8.1 PB-001: Ransomware Response

**Trigger:** Risk score ≥ 85 with `ransomware_behavior` incident type

**Automated Steps:**
```yaml
id: PB-001
name: Ransomware Containment
auto_trigger: true
trigger:
  incident_type: ransomware_behavior
  risk_score_gte: 85
steps:
  - action: kill_process
    params: { pid: "$.incident.primary_pid" }
    on_failure: continue
  - action: isolate_host
    params:
      host_id: "$.incident.host_id"
      preserve_channels: [r3trive-c2, management-vlan]
  - action: quarantine_file
    params: { paths: "$.incident.artifact_paths" }
  - action: plugin.pagerduty.create_incident
    params:
      title: "RANSOMWARE DETECTED: {{ $.incident.host.hostname }}"
      priority: P1
      on_call_schedule: ir-team
  - action: plugin.slack.send
    params:
      channel: "#security-incidents"
      message: ":rotating_light: RANSOMWARE on {{ $.host.hostname }} — Host isolated. INC: {{ $.incident.id }}"
```

**Manual Steps (Tier 3):**
1. Verify isolation is effective (check network connectivity from isolated host)
2. Preserve forensic copy of encrypted files (before any cleanup)
3. Identify ransomware family (`r3trive investigate <malware_path>`)
4. Check backup integrity and recoverability
5. Determine blast radius (what did this host have access to?)
6. Notify Legal if customer data may be involved
7. Begin eradication (reimage from clean baseline)

---

### 8.2 PB-002: Credential Theft Response

**Trigger:** LSASS access from non-trusted process (R3T-CRED-001)

**Automated Steps:**
```yaml
id: PB-002
name: Credential Theft Response
auto_trigger: false          # Requires analyst approval
trigger:
  rule_id: R3T-CRED-001
  confidence_gte: 0.8
steps:
  - action: alert
    params: { channel: pagerduty, severity: critical }
  - action: collect_evidence
    params:
      types: [process_memory, network_connections, open_files]
      pid: "$.alert.data.source.pid"
```

**Manual Steps (Tier 2/3):**
1. Identify the tool used (Mimikatz, ProcDump, CobaltStrike, etc.)
2. Determine what credentials were accessible (domain accounts on this host)
3. Disable or force-reset ALL accounts that were logged into this host
4. Check for lateral movement from this host (last 2h)
5. Revoke Kerberos tickets fleet-wide for affected users
6. Investigate how attacker reached this point (trace parent process chain)
7. Determine if this is initial access or post-exploitation

---

### 8.3 PB-003: Suspicious Outbound Connection

**Trigger:** Beaconing detection (regular interval outbound) or connection to known-bad IP

```yaml
id: PB-003
name: Suspicious Outbound C2 Block
auto_trigger: true
trigger:
  any:
    - rule_id: R3T-C2-001    # beaconing
    - ioc_match: true
      ioc_type: ip
      confidence_gte: 80
steps:
  - action: block_ip
    params:
      ip: "$.event.data.remote_ip"
      direction: outbound
      duration: 24h
      scope: fleet
  - action: kill_connection
    params:
      connection_id: "$.event.data.connection_id"
  - action: alert
    params: { channel: slack, severity: high }
```

**Manual Steps:**
1. Identify what process initiated the connection
2. Investigate the binary (YARA scan, PE analysis)
3. Check if the IP is a Tor exit node (reduces confidence of attribution)
4. Search for this IP contact across all hosts in last 30 days
5. Determine initial access vector for the malware

---

### 8.4 PB-004: Phishing Email Indicator

**Trigger:** Document with macro opened followed by shell or network connection

**Automated Steps:**
- Alert Tier 2 analyst
- Collect process tree evidence

**Manual Steps (Tier 2):**
1. Identify the document filename and sender (via email plugin or manual check)
2. Extract any URLs, attachments, or IOCs from the document
3. Search email gateway logs for recipients of this email
4. Send phishing takedown notification (IT/email admin)
5. Search all endpoints for the document hash
6. Notify any additional recipients to delete without opening

---

## 9. Metrics and KPIs

### 9.1 Operational Metrics (Daily)

```bash
# Generate daily metrics report
r3trive report daily --output daily-report.json

# Key metrics:
# - Alerts generated / closed / escalated
# - MTTR (Mean Time to Respond) by severity
# - False positive rate by rule
# - Active incidents count by severity
# - Hunt coverage (techniques hunted)
```

| KPI | Target | Alert Threshold |
|---|---|---|
| MTTR Critical | < 1 hour | > 2 hours |
| MTTR High | < 4 hours | > 8 hours |
| False positive rate | < 15% | > 30% |
| Alert queue age (Critical) | < 15 min | > 30 min |
| Detection-to-alert latency | < 10ms p99 | > 100ms p99 |
| Agent coverage | > 98% | < 95% |
| Open critical incidents | 0 uninvestigated | > 3 |

### 9.2 Detection Effectiveness Metrics (Weekly)

| Metric | Description |
|---|---|
| Detection rate | % of simulated attacks detected (red team) |
| ATT&CK coverage | % of ATT&CK techniques with active detection |
| Dwell time | Average time from initial compromise to detection |
| Noise ratio | Alerts per true positive |
| Rule hit rate | % of rules that fired at least once in the period |
| Suppression coverage | % of false positives caught by suppressions |

### 9.3 SOC Efficiency Metrics (Monthly)

| Metric | Description |
|---|---|
| Analyst workload | Alerts per analyst per day |
| Escalation rate | % of T1 alerts escalated to T2 |
| AI assistance rate | % of investigations using AI explain |
| Hunt coverage | # unique techniques hunted per month |
| Playbook automation rate | % of incidents with automated first response |

---

## 10. Role-Based Procedures

### 10.1 Tier 1 Analyst — Daily Checklist

**Start of Shift:**
```bash
# 1. Review shift handoff summary
r3trive summarize --since "8h ago"

# 2. Check platform health
r3trive health

# 3. Review open alert queue
r3trive alerts list --status new --sort severity:desc
```

**During Shift:**
- Triage all incoming alerts within SLA
- Document every decision in alert notes
- Escalate according to escalation matrix
- Update any assigned incidents at least every 2 hours

**End of Shift:**
```bash
# Generate handoff summary
r3trive summarize --since "8h ago" --format shift-handoff
```

### 10.2 Tier 2 Analyst — Weekly Checklist

- [ ] Review all false positive submissions from last week, validate suppression rules
- [ ] Run weekly scheduled threat hunt (rotate hunt packages weekly)
- [ ] Review rule statistics for excessive false positives, tune top offenders
- [ ] Check for new Sigma rules to import
- [ ] Update IOC feeds and verify synchronization
- [ ] Review AI feedback scores, report consistent low-quality responses

### 10.3 SOC Engineer — Monthly Checklist

- [ ] Review and update detection rule library (add community rules, remove outdated)
- [ ] Validate all playbooks against current IR process
- [ ] Test alert-to-notification pipeline end-to-end
- [ ] Review suppression rule expiry, revalidate or remove expired suppressions
- [ ] Test backup and restore of event database
- [ ] Review API key expiry for integrations
- [ ] Update ATT&CK knowledge base in AI analyst layer
- [ ] Run AI benchmark suite, report quality regression

---

## 11. Integration Guides

### 11.1 Splunk Integration

```yaml
# r3trive plugin configure com.r3trive.splunk
plugins:
  splunk:
    hec_url: https://splunk.corp.com:8088/services/collector
    hec_token: "${SPLUNK_HEC_TOKEN}"
    index: security_events
    sourcetype: r3trive:event
    min_severity: medium
    batch_size: 100
    flush_interval: 5s
```

Splunk search examples:
```
# All R3TRIVE critical alerts last 24h
index=security_events sourcetype="r3trive:alert" severity=critical earliest=-24h

# Incidents by ATT&CK technique
index=security_events sourcetype="r3trive:incident"
| stats count by attack_techniques{}

# MTTA by severity
index=security_events sourcetype="r3trive:alert"
| eval response_time=(acknowledged_at - created_at)/60
| stats avg(response_time) by severity
```

### 11.2 Elastic/Kibana Integration

```yaml
plugins:
  elastic:
    elasticsearch_url: https://elastic.corp.com:9200
    api_key: "${ELASTIC_API_KEY}"
    index_pattern: r3trive-{type}-{date}  # r3trive-events-2024.03.15
    pipeline: r3trive-ingest
    min_severity: low
```

### 11.3 PagerDuty Integration

```yaml
plugins:
  pagerduty:
    integration_key: "${PAGERDUTY_INTEGRATION_KEY}"
    min_severity: high
    severity_mapping:
      critical: critical
      high: error
      medium: warning
      low: info
    deduplicate_key: "{{ incident_id }}"
    auto_resolve_on_incident_close: true
```

### 11.4 Jira Integration

```yaml
plugins:
  jira:
    url: https://corp.atlassian.net
    api_token: "${JIRA_API_TOKEN}"
    email: "security-bot@corp.com"
    project: SEC
    issue_type: Security Incident
    min_risk_score: 50
    field_mapping:
      summary: "[R3TRIVE] {{ incident.name }}"
      priority:
        P1: Highest
        P2: High
        P3: Medium
        P4: Low
      description: "{{ incident.ai_summary }}\n\n*Incident ID:* {{ incident.id }}\n*Risk Score:* {{ incident.risk_score }}"
    auto_close_on_resolve: true
```

### 11.5 Microsoft Teams Integration

```yaml
plugins:
  teams:
    webhook_url: "${TEAMS_WEBHOOK_URL}"
    min_severity: high
    card_template: adaptive     # adaptive | simple
    channel_routing:
      critical: "https://teams-webhook-critical"
      high: "https://teams-webhook-standard"
```

---

*End of SOC_WORKFLOW.md*
*Related: AI_ANALYST_SPEC.md, SYSTEM_ARCHITECTURE.md, API_REFERENCE.md*
