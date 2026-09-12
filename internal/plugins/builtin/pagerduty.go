package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/plugins"
)

// PagerDutyPlugin creates and resolves incidents via PagerDuty Events API v2.
type PagerDutyPlugin struct {
	routingKey string
	endpoint   string
	client     *http.Client
}

func NewPagerDutyPlugin() *PagerDutyPlugin {
	return &PagerDutyPlugin{
		endpoint: "https://events.pagerduty.com/v2/enqueue",
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *PagerDutyPlugin) Metadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		ID:          "com.r3trive.pagerduty",
		Name:        "PagerDuty Integration",
		Version:     "1.0.0",
		APIVersion:  plugins.CurrentAPIVersion,
		Type:        plugins.PluginTypeAction,
		Description: "Trigger and resolve incidents via PagerDuty Events API v2",
	}
}

func (p *PagerDutyPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	if key, ok := config["routing_key"].(string); ok {
		p.routingKey = key
	}
	return nil
}

func (p *PagerDutyPlugin) Close() error {
	return nil
}

func (p *PagerDutyPlugin) ExecuteAction(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	incidentID, _ := params["incident_id"].(string)
	summary, _ := params["summary"].(string)
	severity, _ := params["severity"].(string)

	if severity == "" {
		severity = "critical"
	}
	if summary == "" {
		summary = "R3TRIVE Incident Triggered"
	}

	eventAction := "trigger"
	if action == "resolve_incident" {
		eventAction = "resolve"
	}

	if p.routingKey == "" {
		return map[string]interface{}{
			"status":       "simulated",
			"event_action": eventAction,
			"dedup_key":    incidentID,
		}, nil
	}

	body := map[string]interface{}{
		"routing_key":  p.routingKey,
		"event_action": eventAction,
		"dedup_key":    incidentID,
		"payload": map[string]interface{}{
			"summary":  summary,
			"severity": severity,
			"source":   "r3trive",
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pagerduty request failed: %w", err)
	}
	defer resp.Body.Close()

	return map[string]interface{}{
		"status":     "delivered",
		"statusCode": resp.StatusCode,
	}, nil
}

var _ plugins.ActionPlugin = (*PagerDutyPlugin)(nil)
