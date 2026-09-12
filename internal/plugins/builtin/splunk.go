package builtin

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

// SplunkPlugin exports events to Splunk HTTP Event Collector (HEC).
type SplunkPlugin struct {
	hecURL     string
	token      string
	index      string
	sourceType string
	client     *http.Client
}

func NewSplunkPlugin() *SplunkPlugin {
	return &SplunkPlugin{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *SplunkPlugin) Metadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		ID:          "com.r3trive.splunk",
		Name:        "Splunk HEC Forwarder",
		Version:     "1.0.0",
		APIVersion:  plugins.CurrentAPIVersion,
		Type:        plugins.PluginTypeOutput,
		Description: "Forward telemetry events and alerts to Splunk HTTP Event Collector",
	}
}

func (p *SplunkPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	if url, ok := config["hec_url"].(string); ok {
		p.hecURL = url
	}
	if token, ok := config["token"].(string); ok {
		p.token = token
	}
	p.index = "main"
	if idx, ok := config["index"].(string); ok && idx != "" {
		p.index = idx
	}
	p.sourceType = "r3trive:event"
	return nil
}

func (p *SplunkPlugin) Close() error {
	return nil
}

func (p *SplunkPlugin) EmitEvent(ctx context.Context, evt event.Event) error {
	payload := map[string]interface{}{
		"time":       evt.Timestamp.Unix(),
		"host":       evt.Host.Hostname,
		"source":     "r3trive",
		"sourcetype": p.sourceType,
		"index":      p.index,
		"event":      evt,
	}
	return p.sendPayload(ctx, payload)
}

func (p *SplunkPlugin) EmitAlert(ctx context.Context, alert event.Alert) error {
	payload := map[string]interface{}{
		"time":       alert.Timestamp.Unix(),
		"source":     "r3trive",
		"sourcetype": "r3trive:alert",
		"index":      p.index,
		"event":      alert,
	}
	return p.sendPayload(ctx, payload)
}

func (p *SplunkPlugin) sendPayload(ctx context.Context, payload map[string]interface{}) error {
	if p.hecURL == "" {
		return nil // unconfigured mock/noop
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.hecURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send splunk event: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

var _ plugins.OutputPlugin = (*SplunkPlugin)(nil)
