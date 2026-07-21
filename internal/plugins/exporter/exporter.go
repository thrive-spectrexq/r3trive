package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ExporterType specifies the target SIEM/Webhook exporter type.
type ExporterType string

const (
	ExporterWebhook ExporterType = "webhook"
	ExporterElastic ExporterType = "elastic"
	ExporterSplunk  ExporterType = "splunk"
)

// Config holds exporter parameters.
type Config struct {
	Type     ExporterType      `json:"type"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
	Timeout  time.Duration     `json:"timeout,omitempty"`
	Disabled bool              `json:"disabled"`
}

// Exporter manages dispatching alerts and incidents to external SIEM/SOAR platforms.
type Exporter struct {
	cfg        Config
	httpClient *http.Client
}

// New creates a new Exporter instance.
func New(cfg Config) *Exporter {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &Exporter{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// SendAlert exports a correlated alert payload.
func (e *Exporter) SendAlert(ctx context.Context, alert event.Alert) error {
	if e.cfg.Disabled || e.cfg.URL == "" {
		return nil
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshalling alert: %w", err)
	}

	return e.dispatch(ctx, payload)
}

// SendIncident exports an incident record to external webhook / SIEM.
func (e *Exporter) SendIncident(ctx context.Context, incident event.Incident) error {
	if e.cfg.Disabled || e.cfg.URL == "" {
		return nil
	}

	payload, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("marshalling incident: %w", err)
	}

	return e.dispatch(ctx, payload)
}

func (e *Exporter) dispatch(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "R3TRIVE-SIEM-Exporter/1.0")

	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}

	slog.Info("exporting security payload to SIEM", "type", e.cfg.Type, "url", e.cfg.URL)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http dispatch error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SIEM exporter returned non-2xx status code: %d", resp.StatusCode)
	}

	return nil
}
