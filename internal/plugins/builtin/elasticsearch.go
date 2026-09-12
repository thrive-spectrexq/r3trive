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

// ElasticsearchPlugin indexes events and alerts into Elasticsearch using _bulk API.
type ElasticsearchPlugin struct {
	esURL       string
	apiKey      string
	indexPrefix string
	client      *http.Client
}

func NewElasticsearchPlugin() *ElasticsearchPlugin {
	return &ElasticsearchPlugin{
		indexPrefix: "r3trive",
		client:      &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *ElasticsearchPlugin) Metadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		ID:          "com.r3trive.elasticsearch",
		Name:        "Elasticsearch Forwarder",
		Version:     "1.0.0",
		APIVersion:  plugins.CurrentAPIVersion,
		Type:        plugins.PluginTypeOutput,
		Description: "Index security events into Elasticsearch with daily time-series indexes",
	}
}

func (p *ElasticsearchPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	if url, ok := config["url"].(string); ok {
		p.esURL = url
	}
	if key, ok := config["api_key"].(string); ok {
		p.apiKey = key
	}
	if prefix, ok := config["index_prefix"].(string); ok && prefix != "" {
		p.indexPrefix = prefix
	}
	return nil
}

func (p *ElasticsearchPlugin) Close() error {
	return nil
}

func (p *ElasticsearchPlugin) EmitEvent(ctx context.Context, evt event.Event) error {
	index := fmt.Sprintf("%s-events-%s", p.indexPrefix, evt.Timestamp.Format("2006.01.02"))
	return p.indexDoc(ctx, index, evt.ID, evt)
}

func (p *ElasticsearchPlugin) EmitAlert(ctx context.Context, alert event.Alert) error {
	index := fmt.Sprintf("%s-alerts-%s", p.indexPrefix, alert.Timestamp.Format("2006.01.02"))
	return p.indexDoc(ctx, index, alert.ID, alert)
}

func (p *ElasticsearchPlugin) indexDoc(ctx context.Context, index, id string, doc interface{}) error {
	if p.esURL == "" {
		return nil
	}
	endpoint := fmt.Sprintf("%s/%s/_doc/%s", p.esURL, index, id)
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if p.apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+p.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("elasticsearch index request failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

var _ plugins.OutputPlugin = (*ElasticsearchPlugin)(nil)
