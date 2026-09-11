# PLUGIN_SDK.md

**R3TRIVE Plugin SDK Reference**
Version: 1.0.0
Status: Draft / Architectural Specification

> [!NOTE]
> **Implementation Status**: In-process timeout bounded sandbox execution and output export plugins are implemented in `internal/plugins`. Multi-process gRPC plugin loader and namespace container isolation are currently `[PLANNED]` / `[NOT YET IMPLEMENTED]`.

---

## Table of Contents

1. [Plugin System Overview](#1-plugin-system-overview)
2. [Plugin Types](#2-plugin-types)
3. [Plugin Architecture](#3-plugin-architecture)
4. [Getting Started](#4-getting-started)
5. [Plugin Manifest](#5-plugin-manifest)
6. [Plugin Interface (gRPC)](#6-plugin-interface-grpc)
7. [Writing a Plugin in Go](#7-writing-a-plugin-in-go)
8. [Writing a Plugin in Python](#8-writing-a-plugin-in-python)
9. [Plugin Lifecycle](#9-plugin-lifecycle)
10. [Security Model for Plugins](#10-security-model-for-plugins)
11. [Testing Plugins](#11-testing-plugins)
12. [Publishing Plugins](#12-publishing-plugins)
13. [Reference Plugins](#13-reference-plugins)

---

## 1. Plugin System Overview

R3TRIVE's plugin system allows third-party developers to extend the platform without modifying core code. Plugins run as isolated processes and communicate with R3TRIVE core via gRPC over Unix domain sockets.

### 1.1 What Plugins Can Do

- **Receive** events, alerts, and incidents from R3TRIVE
- **Send** events from external sources into R3TRIVE
- **Enrich** events with additional context (GeoIP, CMDB, identity)
- **Execute** custom response actions
- **Query** R3TRIVE's event and incident database
- **Provide** additional threat intelligence sources

### 1.2 What Plugins Cannot Do

- Access raw OS events (only the normalized event stream)
- Modify the event log (tamper-evident log is read-only)
- Escalate their own privileges
- Communicate directly with other plugins
- Load or unload detection rules (only core manages this)

---

## 2. Plugin Types

| Type | Interface | Primary Use Case | Direction |
|---|---|---|---|
| `input` | EventSource | Ingest events from external systems | External → R3TRIVE |
| `output` | EventSink | Send alerts/incidents to SIEMs, ticketing | R3TRIVE → External |
| `enrichment` | Enricher | Add context to events (GeoIP, CMDB lookup) | Bidirectional |
| `action` | ActionHandler | New response action types (custom kill, revoke) | R3TRIVE → External |
| `intelligence` | IntelSource | Additional IOC/threat feed sources | External → R3TRIVE |
| `hybrid` | Multiple | Combines multiple types (e.g., SOAR integration) | Bidirectional |

---

## 3. Plugin Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  R3TRIVE Core Process                                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Plugin Manager                                            │  │
│  │  ├── Plugin Registry (loaded plugins)                      │  │
│  │  ├── Lifecycle Manager (start/stop/health)                 │  │
│  │  └── gRPC Server (Unix socket per plugin)                  │  │
│  └────────────────────┬───────────────────────────────────────┘  │
│                       │ Unix Domain Socket                       │
└───────────────────────┼──────────────────────────────────────────┘
                        │
┌───────────────────────┼──────────────────────────────────────────┐
│  Plugin Process       │                                          │
│                       │                                          │
│  ┌────────────────────▼───────────────────────────────────────┐  │
│  │  gRPC Client                                               │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │  Plugin Business Logic                                     │  │
│  │  (SIEM forwarder, SOAR bridge, enrichment lookup, etc.)    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Resource Limits (cgroup):                                       │
│  CPU: max 20% / plugin                                           │
│  RAM: max 512MB / plugin                                         │
│  Network: configurable allowlist                                 │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Getting Started

### 4.1 Prerequisites

- Go 1.22+ or Python 3.13+ (or any language with gRPC support)
- R3TRIVE installed (for testing)
- `r3trive plugin scaffold` command (generates boilerplate)

### 4.2 Scaffold a New Plugin

```bash
r3trive plugin scaffold --name my-plugin --type output --lang go

# Generated structure:
# my-plugin/
# ├── plugin.yaml          # Plugin manifest
# ├── main.go              # Plugin entry point
# ├── handler.go           # Event handler logic
# ├── config.go            # Configuration schema
# ├── Makefile             # Build targets
# └── tests/
#     ├── handler_test.go
#     └── fixtures/
```

### 4.3 Build and Install Locally

```bash
cd my-plugin
make build

# Install for local testing
r3trive plugin install --local ./dist/my-plugin_linux_amd64
```

### 4.4 Test Against R3TRIVE

```bash
# Start R3TRIVE with plugin in development mode
r3trive monitor --plugin-dev ./my-plugin/dist/my-plugin_linux_amd64

# Generate a test event
r3trive test emit --event process.create --template office_shell
```

---

## 5. Plugin Manifest

Every plugin must include a `plugin.yaml` manifest:

```yaml
# plugin.yaml
apiVersion: r3trive.io/v1
kind: Plugin

metadata:
  id: com.example.my-siem-forwarder          # Reverse-DNS style unique ID
  name: My SIEM Forwarder
  version: 1.2.3
  description: Forwards R3TRIVE alerts to My SIEM via syslog
  author: Example Corp <security@example.com>
  homepage: https://github.com/example/r3trive-my-siem
  license: MIT

type: output                                  # input | output | enrichment | action | intelligence | hybrid

# Interfaces implemented
interfaces:
  - EventSink

# R3TRIVE version compatibility
compatibility:
  r3trive: ">=1.0.0 <2.0.0"

# Configuration schema (JSON Schema)
config:
  schema:
    type: object
    properties:
      siem_host:
        type: string
        description: SIEM server hostname
      siem_port:
        type: integer
        default: 514
      protocol:
        type: string
        enum: [tcp, udp, tls]
        default: tls
      api_key:
        type: string
        description: SIEM API key
        secret: true                          # Marked as secret — masked in logs
    required: [siem_host, api_key]

# Events this plugin subscribes to (output/enrichment plugins)
subscriptions:
  events:
    - "alert.*"                               # All alert events
    - "incident.created"
    - "incident.updated"
  min_severity: medium                        # Only receive medium and above

# Actions this plugin provides (action plugins)
actions: []

# Permissions requested
permissions:
  - read:events
  - read:alerts
  - read:incidents
  # NOT: write:events, write:rules, admin

# Resource limits (overrides defaults)
resources:
  cpu_percent: 10
  memory_mb: 256
  network:
    allowed_hosts:
      - "${config.siem_host}"

# Health check
health:
  endpoint: /health                           # gRPC health check method
  interval: 30s
  timeout: 5s

# Signing (required for published plugins)
signature:
  public_key: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
  signed_checksum: sha256:abc123...
```

---

## 6. Plugin Interface (gRPC)

### 6.1 Proto Definition

```protobuf
syntax = "proto3";

package r3trive.plugin.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/struct.proto";

// ─── Core Event Types ──────────────────────────────────────────

message Event {
  string id = 1;
  google.protobuf.Timestamp timestamp = 2;
  string type = 3;                            // e.g., "process.create"
  Severity severity = 4;
  Host host = 5;
  google.protobuf.Struct data = 6;
  map<string, string> enrichments = 7;
}

message Alert {
  string id = 1;
  google.protobuf.Timestamp timestamp = 2;
  string rule_id = 3;
  string rule_name = 4;
  Severity severity = 5;
  float confidence = 6;
  string event_id = 7;
  AttackInfo attack = 8;
  AlertStatus status = 9;
}

message Incident {
  string id = 1;
  google.protobuf.Timestamp created_at = 2;
  google.protobuf.Timestamp updated_at = 3;
  string name = 4;
  Severity severity = 5;
  float risk_score = 6;
  repeated string alert_ids = 7;
  repeated AttackInfo attack_techniques = 8;
  IncidentStatus status = 9;
  string host_id = 10;
  string summary = 11;
}

// ─── Plugin Interfaces ─────────────────────────────────────────

// EventSink: output plugins implement this
service EventSink {
  rpc OnAlert(Alert) returns (SinkResponse);
  rpc OnIncident(Incident) returns (SinkResponse);
  rpc OnEvent(Event) returns (SinkResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

// EventSource: input plugins implement this
service EventSource {
  rpc StartStream(StartStreamRequest) returns (stream Event);
  rpc StopStream(StopStreamRequest) returns (StopStreamResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

// Enricher: enrichment plugins implement this
service Enricher {
  rpc Enrich(EnrichRequest) returns (EnrichResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

// ActionHandler: action plugins implement this
service ActionHandler {
  rpc Execute(ActionRequest) returns (ActionResponse);
  rpc Rollback(RollbackRequest) returns (RollbackResponse);
  rpc ListActions(ListActionsRequest) returns (ListActionsResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

// IntelSource: intelligence plugins implement this
service IntelSource {
  rpc GetIOCs(GetIOCsRequest) returns (GetIOCsResponse);
  rpc SubscribeIOCs(SubscribeIOCsRequest) returns (stream IOCUpdate);
  rpc CheckReputation(CheckReputationRequest) returns (ReputationResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

// ─── Supporting Types ──────────────────────────────────────────

enum Severity {
  SEVERITY_UNSPECIFIED = 0;
  SEVERITY_LOW = 1;
  SEVERITY_MEDIUM = 2;
  SEVERITY_HIGH = 3;
  SEVERITY_CRITICAL = 4;
}

message Host {
  string id = 1;
  string hostname = 2;
  string os = 3;
  string os_version = 4;
  string arch = 5;
  repeated string tags = 6;
}

message AttackInfo {
  string tactic = 1;
  string technique = 2;
  string technique_name = 3;
}

message SinkResponse {
  bool success = 1;
  string error = 2;
  string external_id = 3;            // e.g., ticket ID created in external system
}

message EnrichRequest {
  Event event = 1;
  repeated string requested_fields = 2;
}

message EnrichResponse {
  map<string, string> enrichments = 1;
  float confidence = 2;
}

message ActionRequest {
  string action_id = 1;
  string incident_id = 2;
  string host_id = 3;
  google.protobuf.Struct params = 4;
  bool dry_run = 5;
}

message ActionResponse {
  bool success = 1;
  string error = 2;
  string rollback_id = 3;
  string description = 4;
}

message HealthRequest {}

message HealthResponse {
  enum Status {
    HEALTHY = 0;
    DEGRADED = 1;
    UNHEALTHY = 2;
  }
  Status status = 1;
  string message = 2;
}
```

---

## 7. Writing a Plugin in Go

### 7.1 Complete Output Plugin Example (Slack Notifier)

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "os"

    pluginv1 "github.com/thrive-spectrexq/r3trive-sdk-go/plugin/v1"
    "google.golang.org/grpc"
)

// SlackPlugin forwards critical incidents to Slack.
type SlackPlugin struct {
    pluginv1.UnimplementedEventSinkServer
    webhookURL string
    httpClient *http.Client
}

// OnAlert is called for every new alert.
func (p *SlackPlugin) OnAlert(ctx context.Context, alert *pluginv1.Alert) (*pluginv1.SinkResponse, error) {
    // Only notify on critical alerts
    if alert.Severity != pluginv1.Severity_SEVERITY_CRITICAL {
        return &pluginv1.SinkResponse{Success: true}, nil
    }

    message := fmt.Sprintf(
        ":rotating_light: *Critical Alert*: %s\nHost: %s\nATT&CK: %s",
        alert.RuleName,
        alert.GetHost().GetHostname(),
        alert.GetAttack().GetTechnique(),
    )

    if err := p.sendToSlack(message); err != nil {
        return &pluginv1.SinkResponse{Success: false, Error: err.Error()}, nil
    }

    return &pluginv1.SinkResponse{Success: true}, nil
}

// OnIncident is called for every new/updated incident.
func (p *SlackPlugin) OnIncident(ctx context.Context, incident *pluginv1.Incident) (*pluginv1.SinkResponse, error) {
    if incident.RiskScore < 80 {
        return &pluginv1.SinkResponse{Success: true}, nil
    }

    message := fmt.Sprintf(
        ":fire: *Incident*: %s\nRisk Score: %.0f\nSummary: %s",
        incident.Name,
        incident.RiskScore,
        incident.Summary,
    )

    if err := p.sendToSlack(message); err != nil {
        return &pluginv1.SinkResponse{Success: false, Error: err.Error()}, nil
    }

    return &pluginv1.SinkResponse{Success: true}, nil
}

// OnEvent is not used by this plugin.
func (p *SlackPlugin) OnEvent(ctx context.Context, event *pluginv1.Event) (*pluginv1.SinkResponse, error) {
    return &pluginv1.SinkResponse{Success: true}, nil
}

// Health reports plugin health.
func (p *SlackPlugin) Health(ctx context.Context, req *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
    return &pluginv1.HealthResponse{Status: pluginv1.HealthResponse_HEALTHY}, nil
}

func (p *SlackPlugin) sendToSlack(message string) error {
    // ... Slack webhook POST implementation ...
    return nil
}

func main() {
    socketPath := os.Getenv("R3TRIVE_PLUGIN_SOCKET")
    if socketPath == "" {
        log.Fatal("R3TRIVE_PLUGIN_SOCKET not set")
    }

    webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
    if webhookURL == "" {
        log.Fatal("SLACK_WEBHOOK_URL not set")
    }

    plugin := &SlackPlugin{webhookURL: webhookURL}

    listener, err := net.Listen("unix", socketPath)
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

    server := grpc.NewServer()
    pluginv1.RegisterEventSinkServer(server, plugin)

    log.Printf("Slack plugin listening on %s", socketPath)
    if err := server.Serve(listener); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
```

### 7.2 Go SDK

```bash
go get github.com/thrive-spectrexq/r3trive-sdk-go@latest
```

Key packages:
- `r3trive-sdk-go/plugin/v1` — generated gRPC types and server stubs
- `r3trive-sdk-go/testutil` — plugin testing utilities
- `r3trive-sdk-go/config` — configuration parsing helpers

---

## 8. Writing a Plugin in Python

### 8.1 Complete Enrichment Plugin Example (GeoIP Lookup)

```python
import os
import grpc
from concurrent import futures
import maxminddb

# Generated from proto
import plugin_pb2
import plugin_pb2_grpc

class GeoIPEnricher(plugin_pb2_grpc.EnricherServicer):
    def __init__(self, db_path: str):
        self.reader = maxminddb.open_database(db_path)

    def Enrich(self, request, context):
        event = request.event
        enrichments = {}

        # Extract IP from network events
        remote_ip = event.data.fields.get("remote_ip")
        if remote_ip:
            ip = remote_ip.string_value
            record = self.reader.get(ip)
            if record:
                enrichments["geo.country"] = record.get("country", {}).get("iso_code", "")
                enrichments["geo.city"] = record.get("city", {}).get("names", {}).get("en", "")
                enrichments["geo.asn"] = str(record.get("autonomous_system_number", ""))
                enrichments["geo.org"] = record.get("autonomous_system_organization", "")
                enrichments["geo.is_tor"] = str(record.get("is_anonymous_proxy", False))

        return plugin_pb2.EnrichResponse(
            enrichments=enrichments,
            confidence=0.9
        )

    def Health(self, request, context):
        return plugin_pb2.HealthResponse(
            status=plugin_pb2.HealthResponse.HEALTHY
        )


def serve():
    socket_path = os.environ.get("R3TRIVE_PLUGIN_SOCKET")
    if not socket_path:
        raise ValueError("R3TRIVE_PLUGIN_SOCKET not set")

    db_path = os.environ.get("GEOIP_DB_PATH", "/etc/r3trive/GeoLite2-City.mmdb")

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    plugin_pb2_grpc.add_EnricherServicer_to_server(GeoIPEnricher(db_path), server)
    server.add_insecure_port(f"unix:{socket_path}")
    server.start()
    print(f"GeoIP enricher listening on {socket_path}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
```

### 8.2 Python SDK

```bash
pip install r3trive-plugin-sdk
```

---

## 9. Plugin Lifecycle

### 9.1 States

```
Not Installed → Installed → Configured → Starting → Running
                                                       │
                                              ┌────────┴────────┐
                                           Degraded          Stopping
                                              │                  │
                                           Running            Stopped
```

### 9.2 Startup Sequence

1. R3TRIVE validates plugin manifest and signature
2. Plugin process spawned with `R3TRIVE_PLUGIN_SOCKET` environment variable
3. R3TRIVE connects to plugin's gRPC socket
4. Health check performed
5. Plugin registered in registry
6. Event subscriptions activated (for output/enrichment plugins)
7. Plugin marked as `Running`

### 9.3 Shutdown Sequence

1. R3TRIVE sends shutdown signal via gRPC `Shutdown` RPC
2. Plugin has 10 seconds to flush pending events
3. Plugin process is SIGTERM'd
4. After 15 seconds: SIGKILL if still running

### 9.4 Crash Recovery

- Plugin process crash: R3TRIVE detects socket disconnection
- Restart attempted with exponential backoff (1s, 2s, 4s, 8s, max 60s)
- After 5 failed restarts: plugin marked as `Failed`, admin alert generated
- Events buffered during plugin downtime (configurable buffer size)

---

## 10. Security Model for Plugins

### 10.1 Plugin Signing

Published plugins must be signed with a developer key registered at the R3TRIVE plugin registry. Signature verification:

1. Plugin binary hash computed (SHA256)
2. Signature in manifest verified against developer's registered public key
3. Developer key verified against R3TRIVE plugin registry CA

Unsigned plugins may only be installed with `--allow-unsigned` flag (disabled in production mode).

### 10.2 Permission System

Plugins declare required permissions in their manifest. Users must approve permissions on install:

```
$ r3trive plugin install com.example.siem-forwarder

Plugin: SIEM Forwarder v1.2.3
Publisher: Example Corp (verified)

This plugin requests the following permissions:
  ✓ read:events      Read normalized event stream
  ✓ read:alerts      Read generated alerts
  ✓ read:incidents   Read incident records

Network access:
  ✓ siem.example.com:514

Approve? [y/N]:
```

### 10.3 Sandboxing

On Linux, plugins run in a restricted environment:
- Separate cgroup with CPU/memory limits
- Seccomp filter (allow-list of syscalls)
- No new privileges (`PR_SET_NO_NEW_PRIVS`)
- Read-only filesystem (except plugin-specific temp dir)
- Network access limited to declared allowlist (via eBPF network policy)

---

## 11. Testing Plugins

### 11.1 Unit Testing

```go
import (
    "testing"
    plugintest "github.com/thrive-spectrexq/r3trive-sdk-go/testutil"
)

func TestOnAlert(t *testing.T) {
    plugin := &SlackPlugin{webhookURL: "http://localhost:8080/mock"}

    alert := plugintest.NewAlertBuilder().
        WithSeverity(pluginv1.Severity_SEVERITY_CRITICAL).
        WithRuleName("LSASS Dump Detected").
        Build()

    resp, err := plugin.OnAlert(context.Background(), alert)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !resp.Success {
        t.Fatalf("expected success, got: %s", resp.Error)
    }
}
```

### 11.2 Integration Testing

```bash
# Start R3TRIVE in test mode with mock data
r3trive test start --scenario credential_dump

# Plugin receives real events from the test scenario
r3trive plugin test --plugin ./dist/my-plugin --scenario credential_dump --duration 60s
```

### 11.3 Available Test Scenarios

| Scenario | Description |
|---|---|
| `credential_dump` | LSASS dump via Mimikatz simulation |
| `ransomware` | File encryption behavior |
| `reverse_shell` | Outbound shell via Python |
| `lateral_movement` | PsExec lateral movement |
| `data_exfiltration` | Large outbound transfer |
| `persistence` | Registry and startup persistence |

---

## 12. Publishing Plugins

### 12.1 Registration

1. Create a developer account at [plugins.r3trive.io](https://plugins.r3trive.io)
2. Generate a signing key pair: `r3trive plugin keygen --name "My Org"`
3. Submit public key for registration (manual review)
4. Receive signing certificate after approval

### 12.2 Signing and Publishing

```bash
# Sign plugin binary
r3trive plugin sign --key /path/to/private.key --manifest plugin.yaml ./dist/

# Publish to registry
r3trive plugin publish --registry plugins.r3trive.io ./dist/
```

### 12.3 Versioning Policy

- Use semantic versioning (MAJOR.MINOR.PATCH)
- Breaking API changes require major version bump
- Deprecation period: 6 months before removing old major versions
- Security fixes: patch version, backported to last 2 major versions

---

## 13. Reference Plugins

These plugins are maintained by the R3TRIVE team and serve as canonical examples:

| Plugin | Type | Description | Repo |
|---|---|---|---|
| `r3trive-splunk` | output | Forward to Splunk HEC | github.com/r3trive/plugin-splunk |
| `r3trive-elastic` | output | Forward to Elasticsearch | github.com/r3trive/plugin-elastic |
| `r3trive-pagerduty` | output | PagerDuty incident creation | github.com/r3trive/plugin-pagerduty |
| `r3trive-jira` | output + action | Jira ticket creation | github.com/r3trive/plugin-jira |
| `r3trive-servicenow` | output + action | ServiceNow ITSM | github.com/r3trive/plugin-servicenow |
| `r3trive-misp` | intelligence | MISP IOC feed | github.com/r3trive/plugin-misp |
| `r3trive-virustotal` | enrichment + intel | VirusTotal lookups | github.com/r3trive/plugin-virustotal |
| `r3trive-geoip` | enrichment | MaxMind GeoIP | github.com/r3trive/plugin-geoip |
| `r3trive-slack` | output | Slack notifications | github.com/r3trive/plugin-slack |
| `r3trive-teams` | output | Microsoft Teams | github.com/r3trive/plugin-teams |
| `r3trive-crowdstrike` | intelligence + action | CrowdStrike integration | github.com/r3trive/plugin-crowdstrike |
| `r3trive-aws-guardduty` | input | Ingest GuardDuty findings | github.com/r3trive/plugin-aws-guardduty |

---

*End of PLUGIN_SDK.md*
*Related: SYSTEM_ARCHITECTURE.md, API_REFERENCE.md*
