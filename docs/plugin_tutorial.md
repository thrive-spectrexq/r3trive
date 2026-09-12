# Plugin Development Tutorial

This tutorial guides you through creating, testing, and registering custom plugins for R3TRIVE using the Go Plugin SDK (`internal/plugins/sdk.go`).

---

## Table of Contents

1. [SDK Architecture](#1-sdk-architecture)
2. [Plugin Interfaces](#2-plugin-interfaces)
3. [Walkthrough: Building a Discord Webhook Output Plugin](#3-walkthrough-building-a-discord-webhook-output-plugin)
4. [Walkthrough: Building a Custom Action Plugin](#4-walkthrough-building-a-custom-action-plugin)
5. [Registering Plugins](#5-registering-plugins)
6. [Unit Testing Your Plugin](#6-unit-testing-your-plugin)

---

## 1. SDK Architecture

R3TRIVE plugins extend the core detection and response pipeline. Plugins execute within bounded sandboxes where each invocation is governed by:
- Strict timeouts (default 10 seconds per execution).
- Non-blocking asynchronous channels for alert and event distribution.
- Semantic API versioning (`CurrentAPIVersion = "1.0.0"`).

All plugins implement the core `Plugin` interface and one or more specialized capability interfaces.

---

## 2. Plugin Interfaces

The core interface definitions in `internal/plugins/sdk.go`:

```go
type Plugin interface {
    Metadata() PluginMetadata
    Init(ctx context.Context, config map[string]interface{}) error
    Close() error
}

type OutputPlugin interface {
    Plugin
    EmitEvent(ctx context.Context, evt event.Event) error
    EmitAlert(ctx context.Context, alert event.Alert) error
}

type ActionPlugin interface {
    Plugin
    ExecuteAction(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error)
}

type IntelligencePlugin interface {
    Plugin
    LookupIOC(ctx context.Context, iocType string, value string) (map[string]interface{}, error)
}
```

---

## 3. Walkthrough: Building a Discord Webhook Output Plugin

In this example, we build an `OutputPlugin` that dispatches alerts to a Discord webhook channel.

### Step 1: Define the Struct and Metadata

```go
package myplugins

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/thrive-spectrexq/r3trive/internal/plugins"
    "github.com/thrive-spectrexq/r3trive/pkg/event"
)

type DiscordPlugin struct {
    webhookURL string
    client     *http.Client
}

func NewDiscordPlugin() *DiscordPlugin {
    return &DiscordPlugin{
        client: &http.Client{Timeout: 5 * time.Second},
    }
}

func (d *DiscordPlugin) Metadata() plugins.PluginMetadata {
    return plugins.PluginMetadata{
        ID:          "discord-notifier",
        Name:        "Discord Webhook Alert Sink",
        Version:     "1.0.0",
        APIVersion:  plugins.CurrentAPIVersion,
        Type:        plugins.PluginTypeOutput,
        Description: "Posts high and critical security alerts to a Discord channel",
    }
}
```

### Step 2: Implement Init and Close Lifecycle Methods

```go
func (d *DiscordPlugin) Init(ctx context.Context, config map[string]interface{}) error {
    urlVal, ok := config["webhook_url"]
    if !ok {
        return fmt.Errorf("missing required configuration: webhook_url")
    }
    urlStr, ok := urlVal.(string)
    if !ok || urlStr == "" {
        return fmt.Errorf("invalid webhook_url: must be a non-empty string")
    }
    d.webhookURL = urlStr
    return nil
}

func (d *DiscordPlugin) Close() error {
    d.client.CloseIdleConnections()
    return nil
}
```

### Step 3: Implement EmitAlert and EmitEvent

```go
func (d *DiscordPlugin) EmitEvent(ctx context.Context, evt event.Event) error {
    // Optionally filter or ignore raw events
    return nil
}

func (d *DiscordPlugin) EmitAlert(ctx context.Context, alert event.Alert) error {
    // Only forward high and critical alerts
    if alert.Severity != "high" && alert.Severity != "critical" {
        return nil
    }

    payload := map[string]interface{}{
        "content": fmt.Sprintf("[R3TRIVE ALERT] %s: %s (Severity: %s, Host: %s)",
            alert.RuleID, alert.RuleName, alert.Severity, alert.HostID),
    }

    body, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("failed to marshal discord payload: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := d.client.Do(req)
    if err != nil {
        return fmt.Errorf("discord webhook request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        return fmt.Errorf("discord returned status %d", resp.StatusCode)
    }

    return nil
}
```

---

## 4. Walkthrough: Building a Custom Action Plugin

Action plugins allow automated or analyst-initiated response operations, such as revoking API keys or isolating network segments.

```go
package myplugins

import (
    "context"
    "fmt"

    "github.com/thrive-spectrexq/r3trive/internal/plugins"
)

type CloudIAMPlugin struct{}

func (c *CloudIAMPlugin) Metadata() plugins.PluginMetadata {
    return plugins.PluginMetadata{
        ID:          "cloud-iam-responder",
        Name:        "Cloud IAM Credential Revocation",
        Version:     "1.0.0",
        APIVersion:  plugins.CurrentAPIVersion,
        Type:        plugins.PluginTypeAction,
        Description: "Deactivates compromised cloud access keys upon credential theft detection",
    }
}

func (c *CloudIAMPlugin) Init(ctx context.Context, config map[string]interface{}) error {
    return nil
}

func (c *CloudIAMPlugin) Close() error {
    return nil
}

func (c *CloudIAMPlugin) ExecuteAction(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
    switch action {
    case "deactivate_access_key":
        keyID, ok := params["access_key_id"].(string)
        if !ok || keyID == "" {
            return nil, fmt.Errorf("missing access_key_id parameter")
        }
        // Execute revocation via cloud provider SDK
        return map[string]interface{}{
            "status":        "revoked",
            "access_key_id": keyID,
        }, nil
    default:
        return nil, fmt.Errorf("unsupported action: %s", action)
    }
}
```

---

## 5. Registering Plugins

Register your plugin with the R3TRIVE plugin manager during system initialization:

```go
mgr := plugins.NewManager()
discordPlugin := NewDiscordPlugin()

if err := mgr.Register(discordPlugin); err != nil {
    log.Fatalf("failed to register plugin: %v", err)
}

// Initialize plugins with configuration
cfg := map[string]interface{}{
    "webhook_url": "https://discord.com/api/webhooks/...",
}
if err := mgr.InitPlugin("discord-notifier", cfg); err != nil {
    log.Fatalf("failed to initialize discord plugin: %v", err)
}
```

---

## 6. Unit Testing Your Plugin

Use Go standard testing with mock HTTP servers:

```go
func TestDiscordPlugin_EmitAlert(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))
    defer server.Close()

    plugin := NewDiscordPlugin()
    err := plugin.Init(context.Background(), map[string]interface{}{
        "webhook_url": server.URL,
    })
    if err != nil {
        t.Fatalf("Init failed: %v", err)
    }

    alert := event.Alert{
        ID:       "alt-001",
        RuleID:   "RULE-RANSOM-01",
        RuleName: "Ransomware Burst Detected",
        Severity: "critical",
    }

    if err := plugin.EmitAlert(context.Background(), alert); err != nil {
        t.Fatalf("EmitAlert failed: %v", err)
    }
}
```
