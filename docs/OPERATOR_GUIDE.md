# R3TRIVE Operator's Guide

This guide provides operational runbooks, architecture procedures, and production deployment standards for managing and operating R3TRIVE enterprise endpoint detection and response clusters.

---

## 1. Operating Modes & Security Policy

R3TRIVE enforces explicit deployment modes: `development` and `production`.

### Mode Selection
Set via config file (`mode: production`) or environment variable (`R3TRIVE_MODE=production` or `R3TRIVE_ENV=production`).

| Policy Check | Development Mode | Production Mode |
| :--- | :--- | :--- |
| **API Authentication** | Optional (skips auth if empty) | **Mandatory** (`api.api_key` required) |
| **Non-Loopback Binding** | Allowed with warning or flag | **Requires valid TLS** (`tls_cert` & `tls_key`) |
| **Insecure Binding Override** | Allowed via flag | **Prohibited** (`allow_insecure_binding: true` causes startup error) |
| **CORS Origins** | Wildcard `*` allowed | **Explicit allowlist only** (wildcard `*` rejected) |
| **Startup Summary** | Emits effective config log | Emits sanitized config log (credentials masked) |

---

## 2. Configuration Precedence

Configuration parameters are resolved using a strict 4-tier precedence model:

1. **CLI Flags** (e.g. `--log-level debug`, `--config path.yaml`)
2. **Environment Variables** (e.g. `R3TRIVE_LOG_LEVEL=debug`, `R3TRIVE_CONFIG=/etc/r3trive.yaml`)
3. **Configuration File** (Path specified by `--config`, `R3TRIVE_CONFIG`, or default OS paths)
4. **Compiled Defaults** (Safe local developer defaults)

### Configuration Discovery Order
When no path is specified:
1. Environment variable: `R3TRIVE_CONFIG`
2. Working directory: `./r3trive.yaml`
3. System location:
   - Linux / macOS: `/etc/r3trive/r3trive.yaml`
   - Windows: `%PROGRAMDATA%\r3trive\r3trive.yaml` or `%LOCALAPPDATA%\r3trive\r3trive.yaml`

---

## 3. Container & Orchestrator Health Probes

R3TRIVE exposes standard Kubernetes / nomad / systemd operational probes:

### Liveness Probe (`GET /api/v1/live`)
- **Purpose:** Verifies the process is running and event loop is responsive.
- **Status:** Returns HTTP `200 OK` `{"status": "live"}`.
- **Recommended settings:** `initialDelaySeconds: 5`, `periodSeconds: 10`.

### Readiness Probe (`GET /api/v1/ready`)
- **Purpose:** Verifies that the storage backend (SQLite or PostgreSQL) is reachable and healthy before routing traffic.
- **Status:** Returns HTTP `200 OK` `{"status": "ready"}` or HTTP `503 Service Unavailable` `{"status": "unavailable", "error": "..."}`.
- **Recommended settings:** `initialDelaySeconds: 5`, `periodSeconds: 5`.

### Health & Metadata Probe (`GET /api/v1/health`)
- **Purpose:** Provides operational metrics, daemon uptime, version information, and storage connection status.
- **Status:** Returns HTTP `200 OK` with JSON envelope:
  ```json
  {
    "status": "ok",
    "uptime": "2h14m3s",
    "version": "1.0.0",
    "storage": "connected"
  }
  ```

---

## 4. Storage Architecture & Maintenance

R3TRIVE supports two persistent storage backends:

### Embedded SQLite (`driver: sqlite`)
- **Use Case:** Single-node sensor deployments, developer workstations, air-gapped endpoints.
- **Engine:** Pure Go modernc SQLite with Write-Ahead Logging (`PRAGMA journal_mode=WAL`).
- **Connection Pool:** Configured for 25 max open connections and 5 idle connections to optimize concurrent read performance.
- **Queries:** Enforces pagination bounds (`default: 100`, `max: 1000`).

### Enterprise PostgreSQL (`driver: postgres`)
- **Use Case:** Multi-node fleet management, aggregated SOC pipelines, high-ingestion deployments.
- **Driver:** High-throughput `pgx/v5`.
- **Connection Pool:** Managed pool with connection lifetime limits and connection health checks.

### Automated Retention Pruning
R3TRIVE includes a retention manager that archives and purges aged events based on `storage.retention_days`:
- Archives aged events into gzipped JSONL files for compliance retention.
- Invokes atomic indexed pruning: `PruneEvents(ctx, cutoff)`.
- Returns detailed cycle statistics (`events_archived`, `events_purged`, `archive_file`).

---

## 5. Defensive Containment Guardrails & Audit Logging

When responding to critical threats or automated playbook triggers, R3TRIVE applies safety guardrails:

### Allowlist Guardrails
- **PID Protection:** Prohibits killing system init/core processes (PID 1 on Linux/macOS, PID 4 on Windows).
- **Network Protection:** Prohibits blocking loopback (`127.0.0.1`, `localhost`, `0.0.0.0`).
- **Host Protection:** Prohibits isolating loopback interfaces.

### Tamper-Evident Action Audit Logging
Every response action attempted (whether manual, playbook, live, or dry-run) generates an immutable `AuditRecord`:
```json
{
  "id": "audit_1789790258090868800",
  "timestamp": "2026-09-19T03:57:38Z",
  "action": "kill_process",
  "params": {"pid": 65394},
  "dry_run": true,
  "success": true
}
```
Audit records are emitted as structured logs and retrievable via `engine.AuditLog()`.

---

## 6. AI Copilot Resilience

The AI investigation client features automatic retries with exponential backoff (`RetryingClient`):
- **Backoff:** Base delay 100ms, doubling per retry up to 3 attempts.
- **Safety:** Respects context deadlines and request timeouts.
- **Offline Fallback:** If upstream models (Ollama or OpenAI) are unreachable, the system gracefully falls back without blocking sensor collection.
