# API_REFERENCE.md

**R3TRIVE API Reference**
Version: 1.0.0
Status: Draft
Base URL: `https://localhost:8443/api/v1`

---

## Table of Contents

1. [API Overview](#1-api-overview)
2. [Authentication](#2-authentication)
3. [Events API](#3-events-api)
4. [Alerts API](#4-alerts-api)
5. [Incidents API](#5-incidents-api)
6. [Hosts API](#6-hosts-api)
7. [Hunt API](#7-hunt-api)
8. [Investigate API](#8-investigate-api)
9. [Response API](#9-response-api)
10. [Intelligence API](#10-intelligence-api)
11. [Rules API](#11-rules-api)
12. [AI API](#12-ai-api)
13. [Config API](#13-config-api)
14. [Streaming API (WebSocket/SSE)](#14-streaming-api)
15. [Error Reference](#15-error-reference)
16. [Rate Limiting](#16-rate-limiting)

---

## 1. API Overview

R3TRIVE exposes a REST API and a WebSocket/SSE streaming API. The REST API is enabled with:

```bash
r3trive serve --bind 0.0.0.0:8443 --tls
```

All endpoints return JSON. Timestamps are ISO 8601 with nanosecond precision.

### 1.1 API Versioning

The API is versioned via URL path (`/api/v1/`). Breaking changes result in a new version. Version `v1` will be maintained for a minimum of 2 years after `v2` release.

### 1.2 Request Format

```
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
X-Request-ID: <client-generated UUID>     # optional, echoed in response
```

### 1.3 Response Envelope

All responses are wrapped in a standard envelope:

```json
{
  "success": true,
  "data": { ... },           // present on success
  "error": null,             // present on error
  "meta": {
    "request_id": "req_01HN2X...",
    "timestamp": "2024-03-15T14:32:01.000000000Z",
    "version": "1.0.0"
  }
}
```

Error response:

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ALERT_NOT_FOUND",
    "message": "Alert with ID 'alt_abc123' not found",
    "details": {}
  },
  "meta": { ... }
}
```

---

## 2. Authentication

### 2.1 API Key Authentication

```http
Authorization: Bearer r3t_sk_live_abc123def456...
```

API keys are generated with:

```bash
r3trive api-key create --name "SOC Dashboard" --role analyst --expires 90d
```

### 2.2 Short-lived Session Token

For interactive sessions (Web UI):

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "analyst@corp.com",
  "password": "...",
  "mfa_code": "123456"
}
```

Response:
```json
{
  "token": "eyJhbGc...",
  "expires_at": "2024-03-15T22:32:01Z",
  "user": {
    "id": "usr_abc123",
    "username": "analyst@corp.com",
    "role": "analyst"
  }
}
```

### 2.3 Roles and Permissions

| Endpoint Category | viewer | analyst | responder | admin |
|---|---|---|---|---|
| Events (read) | ✓ | ✓ | ✓ | ✓ |
| Alerts (read) | ✓ | ✓ | ✓ | ✓ |
| Alerts (update status) | — | ✓ | ✓ | ✓ |
| Incidents (read) | ✓ | ✓ | ✓ | ✓ |
| Hunt | — | ✓ | ✓ | ✓ |
| Investigate | — | ✓ | ✓ | ✓ |
| Response actions | — | — | ✓ | ✓ |
| Rules (read) | ✓ | ✓ | ✓ | ✓ |
| Rules (write) | — | — | — | ✓ |
| Config | — | — | — | ✓ |
| User management | — | — | — | ✓ |

---

## 3. Events API

### 3.1 List Events

```http
GET /api/v1/events
```

Query parameters:

| Parameter | Type | Description | Default |
|---|---|---|---|
| `start` | timestamp | Start of time range | -1h |
| `end` | timestamp | End of time range | now |
| `host_id` | string | Filter by host | — |
| `type` | string | Filter by event type | — |
| `severity` | string | Filter by severity (low/medium/high/critical) | — |
| `limit` | integer | Max results per page | 100 |
| `cursor` | string | Pagination cursor | — |
| `sort` | string | Sort field and order (timestamp:asc, timestamp:desc) | timestamp:desc |

Example:
```http
GET /api/v1/events?start=2024-03-15T14:00:00Z&type=process.create&severity=high&limit=50
```

Response:
```json
{
  "success": true,
  "data": {
    "events": [
      {
        "id": "evt_01HN2X...",
        "timestamp": "2024-03-15T14:32:01.123456789Z",
        "type": "process.create",
        "severity": "high",
        "host": {
          "id": "host_abc123",
          "hostname": "WORKSTATION-01",
          "os": "windows"
        },
        "data": {
          "pid": 12345,
          "name": "powershell.exe",
          "cmdline": "powershell.exe -enc <base64>",
          "parent": {
            "pid": 1001,
            "name": "winword.exe"
          }
        }
      }
    ],
    "pagination": {
      "total": 1423,
      "limit": 50,
      "next_cursor": "cur_abc123"
    }
  }
}
```

### 3.2 Get Event

```http
GET /api/v1/events/{event_id}
```

### 3.3 Stream Events (SSE)

```http
GET /api/v1/events/stream?severity=high&type=process.create
Accept: text/event-stream
```

See [Streaming API](#14-streaming-api).

---

## 4. Alerts API

### 4.1 List Alerts

```http
GET /api/v1/alerts
```

Query parameters:

| Parameter | Type | Description |
|---|---|---|
| `start` / `end` | timestamp | Time range |
| `host_id` | string | Filter by host |
| `severity` | string | Filter by severity |
| `status` | string | Filter by status (new/acknowledged/investigating/true_positive/false_positive/closed) |
| `rule_id` | string | Filter by rule |
| `incident_id` | string | Filter by parent incident |
| `limit` / `cursor` | — | Pagination |

### 4.2 Get Alert

```http
GET /api/v1/alerts/{alert_id}
```

Response includes related event, correlated incident, and ATT&CK mapping.

### 4.3 Update Alert Status

```http
PATCH /api/v1/alerts/{alert_id}
```

Request:
```json
{
  "status": "false_positive",
  "note": "This is our backup tool, adding to allowlist",
  "create_suppression": true,
  "suppression_expires_days": 90
}
```

### 4.4 Bulk Update Alerts

```http
POST /api/v1/alerts/bulk-update
```

Request:
```json
{
  "alert_ids": ["alt_001", "alt_002", "alt_003"],
  "status": "acknowledged",
  "note": "Reviewed during morning triage"
}
```

---

## 5. Incidents API

### 5.1 List Incidents

```http
GET /api/v1/incidents
```

Query parameters:

| Parameter | Type | Description |
|---|---|---|
| `start` / `end` | timestamp | Time range |
| `host_id` | string | Filter by host |
| `severity` | string | Severity filter |
| `status` | string | open / investigating / resolved / closed |
| `risk_score_gte` | float | Minimum risk score (0–100) |
| `technique` | string | ATT&CK technique ID (e.g., T1003.001) |

### 5.2 Get Incident

```http
GET /api/v1/incidents/{incident_id}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "INC-20240315-001",
    "name": "Credential Theft Campaign",
    "severity": "critical",
    "risk_score": 94.2,
    "status": "investigating",
    "created_at": "2024-03-15T14:32:01Z",
    "updated_at": "2024-03-15T14:45:22Z",
    "host": {
      "id": "host_abc123",
      "hostname": "WORKSTATION-01"
    },
    "alert_count": 7,
    "alert_ids": ["alt_001", "alt_002", "..."],
    "attack_techniques": [
      {
        "tactic": "CredentialAccess",
        "technique": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory"
      }
    ],
    "timeline": [
      {
        "timestamp": "2024-03-15T14:32:01Z",
        "type": "alert",
        "summary": "PowerShell spawned by Word"
      },
      {
        "timestamp": "2024-03-15T14:32:15Z",
        "type": "alert",
        "summary": "LSASS memory read"
      }
    ],
    "ai_summary": "An attacker used a malicious Word macro to launch PowerShell...",
    "response_actions": []
  }
}
```

### 5.3 Update Incident

```http
PATCH /api/v1/incidents/{incident_id}
```

Request:
```json
{
  "status": "investigating",
  "assignee": "analyst@corp.com",
  "priority": "P1",
  "note": "Escalated to IR team"
}
```

### 5.4 Get Incident Timeline

```http
GET /api/v1/incidents/{incident_id}/timeline
```

Returns ordered list of alerts, events, and analyst actions with timestamps.

### 5.5 Get Incident Evidence

```http
GET /api/v1/incidents/{incident_id}/evidence
```

Returns collected evidence artifacts (process dumps, file samples, network captures).

---

## 6. Hosts API

### 6.1 List Hosts

```http
GET /api/v1/hosts
```

### 6.2 Get Host

```http
GET /api/v1/hosts/{host_id}
```

Response includes sensor status, active monitoring configuration, recent activity summary, and risk score.

### 6.3 Get Host Risk Score

```http
GET /api/v1/hosts/{host_id}/risk
```

### 6.4 Get Host Activity Summary

```http
GET /api/v1/hosts/{host_id}/summary?period=24h
```

---

## 7. Hunt API

### 7.1 Run Hunt

```http
POST /api/v1/hunt
```

Request:
```json
{
  "scope": {
    "host_ids": ["host_abc123"],          // empty = all hosts
    "tags": ["production"]
  },
  "technique": "T1003.001",               // optional: target specific ATT&CK technique
  "ioc": {
    "type": "ip",
    "value": "185.220.101.47"
  },
  "ruleset": "default",                    // default / custom / path to custom dir
  "timeout": "300s"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "hunt_id": "hunt_01HN2X...",
    "status": "running",
    "started_at": "2024-03-15T14:32:01Z"
  }
}
```

### 7.2 Get Hunt Results

```http
GET /api/v1/hunt/{hunt_id}
```

### 7.3 List Hunt History

```http
GET /api/v1/hunt
```

---

## 8. Investigate API

### 8.1 Investigate File

```http
POST /api/v1/investigate/file
```

Request:
```json
{
  "host_id": "host_abc123",
  "path": "C:\\Users\\jsmith\\Downloads\\invoice.exe",
  "options": {
    "yara": true,
    "strings": true,
    "entropy": true,
    "network_lookup": true
  }
}
```

Response includes: risk score, findings, ATT&CK techniques, IOC matches, YARA matches, binary metadata, strings of interest.

### 8.2 Investigate Process

```http
POST /api/v1/investigate/process
```

Request:
```json
{
  "host_id": "host_abc123",
  "pid": 4821
}
```

### 8.3 Investigate Incident

```http
POST /api/v1/investigate/incident/{incident_id}
```

Triggers deep investigation workflow on an existing incident, adding additional analysis.

---

## 9. Response API

### 9.1 Execute Response Action

```http
POST /api/v1/response/actions
```

Request:
```json
{
  "action": "kill_process",
  "host_id": "host_abc123",
  "params": {
    "pid": 4821
  },
  "incident_id": "INC-20240315-001",
  "dry_run": false,
  "note": "Killing malicious process per IR playbook"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "action_id": "act_01HN2X...",
    "action": "kill_process",
    "status": "success",
    "executed_at": "2024-03-15T14:32:01Z",
    "executed_by": "analyst@corp.com",
    "rollback_id": "rb_01HN2X...",
    "description": "Process 4821 (powershell.exe) terminated successfully"
  }
}
```

Available actions:

| Action | Required Params |
|---|---|
| `kill_process` | `pid` |
| `block_ip` | `ip`, optional: `duration`, `direction` (in/out/both) |
| `quarantine_file` | `path` |
| `isolate_host` | `host_id`, optional: `preserve_channels` |
| `disable_account` | `username` |
| `kill_connection` | `connection_id` |
| `disable_service` | `service_name` |

### 9.2 Rollback Action

```http
POST /api/v1/response/actions/{rollback_id}/rollback
```

### 9.3 List Response Actions

```http
GET /api/v1/response/actions?incident_id={incident_id}
```

### 9.4 Execute Playbook

```http
POST /api/v1/response/playbooks/{playbook_id}/execute
```

Request:
```json
{
  "incident_id": "INC-20240315-001",
  "dry_run": true
}
```

---

## 10. Intelligence API

### 10.1 Add IOC

```http
POST /api/v1/intel/iocs
```

Request:
```json
{
  "type": "ip",
  "value": "185.220.101.47",
  "confidence": 90,
  "tags": ["tor-exit-node", "c2"],
  "source": "analyst",
  "note": "Observed in INC-20240315-001",
  "ttl_days": 90
}
```

### 10.2 Search IOCs

```http
GET /api/v1/intel/iocs?type=ip&value=185.220.101.47
```

### 10.3 Bulk IOC Import

```http
POST /api/v1/intel/iocs/bulk
Content-Type: application/json

{
  "iocs": [ ... ],
  "source": "misp-export",
  "default_ttl_days": 30
}
```

### 10.4 Check Reputation

```http
GET /api/v1/intel/reputation?type=ip&value=8.8.8.8
```

### 10.5 List Threat Feeds

```http
GET /api/v1/intel/feeds
```

---

## 11. Rules API

### 11.1 List Rules

```http
GET /api/v1/rules
```

Query parameters: `type` (behavioral/yara/sigma/correlation), `status` (stable/experimental), `tag`.

### 11.2 Get Rule

```http
GET /api/v1/rules/{rule_id}
```

### 11.3 Create Custom Rule

```http
POST /api/v1/rules
```

Request: Rule in YAML format (see RULE_ENGINE_SPEC.md).

### 11.4 Update Rule

```http
PUT /api/v1/rules/{rule_id}
```

### 11.5 Enable/Disable Rule

```http
PATCH /api/v1/rules/{rule_id}/status
```

```json
{ "enabled": false, "reason": "Too many false positives in this environment" }
```

### 11.6 Get Rule Statistics

```http
GET /api/v1/rules/{rule_id}/stats
```

Returns: hit count, false positive rate, true positive rate, last triggered.

---

## 12. AI API

### 12.1 Explain Incident

```http
POST /api/v1/ai/explain
```

Request:
```json
{
  "incident_id": "INC-20240315-001",
  "format": "analyst",           // analyst | executive | technical
  "include_recommendations": true
}
```

### 12.2 Summarize Activity

```http
POST /api/v1/ai/summarize
```

Request:
```json
{
  "period": "24h",
  "scope": {
    "host_ids": [],              // empty = all
    "min_severity": "medium"
  }
}
```

### 12.3 Generate Rule

```http
POST /api/v1/ai/generate-rule
```

Request:
```json
{
  "incident_id": "INC-20240315-001",
  "rule_type": "behavioral",     // behavioral | yara | sigma
  "context": "Focus on the PowerShell obfuscation pattern"
}
```

### 12.4 Ask Security Question

```http
POST /api/v1/ai/ask
```

Request:
```json
{
  "question": "What lateral movement techniques were used in the last 24 hours?",
  "context_window": "24h",
  "host_id": "host_abc123"
}
```

### 12.5 Reconstruct Attack Chain

```http
POST /api/v1/ai/attack-chain
```

Request:
```json
{
  "incident_id": "INC-20240315-001"
}
```

---

## 13. Config API

### 13.1 Get Configuration

```http
GET /api/v1/config
```

Returns sanitized configuration (secrets redacted).

### 13.2 Update Configuration

```http
PATCH /api/v1/config
```

Only available to `admin` role. Triggers configuration reload.

### 13.3 Validate Configuration

```http
POST /api/v1/config/validate
```

Request: proposed configuration object. Returns validation result without applying.

---

## 14. Streaming API

### 14.1 Server-Sent Events (SSE)

Connect for real-time event/alert streams:

```http
GET /api/v1/stream
Accept: text/event-stream
Authorization: Bearer <token>
```

Query parameters: `types` (comma-separated event types), `severity`, `host_id`.

SSE event format:
```
event: alert
data: {"id":"alt_001","severity":"critical","rule_name":"LSASS Dump","..."}

event: incident
data: {"id":"INC-001","name":"Credential Theft","risk_score":94.2,"..."}

event: heartbeat
data: {"timestamp":"2024-03-15T14:32:01Z"}
```

### 14.2 WebSocket

For bidirectional communication (enterprise dashboard):

```
wss://localhost:8443/api/v1/ws
```

Supports: subscribe/unsubscribe to event streams, real-time queries, command execution.

---

## 15. Error Reference

| Code | HTTP Status | Description |
|---|---|---|
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient permissions for this action |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `VALIDATION_ERROR` | 422 | Request body failed validation |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `AI_UNAVAILABLE` | 503 | AI backend not reachable |
| `SENSOR_ERROR` | 503 | Required sensor not running |
| `HOST_UNREACHABLE` | 503 | Target host agent not reachable |
| `ACTION_FAILED` | 500 | Response action execution failed |
| `RULE_SYNTAX_ERROR` | 422 | Detection rule syntax invalid |
| `YARA_COMPILE_ERROR` | 422 | YARA rule failed to compile |

---

## 16. Rate Limiting

| Endpoint Category | Rate Limit |
|---|---|
| Authentication | 5 requests/minute |
| Read endpoints | 1,000 requests/minute |
| Write endpoints | 100 requests/minute |
| AI endpoints | 20 requests/minute |
| Hunt | 5 concurrent hunts |
| Response actions | 60 per hour |

Rate limit headers returned on all responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1710510000
Retry-After: 30                    # only on 429 responses
```

---

*End of API_REFERENCE.md*
*Related: SYSTEM_ARCHITECTURE.md, PLUGIN_SDK.md*
