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

// MISPPlugin queries and synchronizes threat indicators from a MISP instance.
type MISPPlugin struct {
	baseURL string
	authKey string
	client  *http.Client
}

func NewMISPPlugin() *MISPPlugin {
	return &MISPPlugin{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *MISPPlugin) Metadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		ID:          "com.r3trive.misp",
		Name:        "MISP Threat Sharing",
		Version:     "1.0.0",
		APIVersion:  plugins.CurrentAPIVersion,
		Type:        plugins.PluginTypeIntelligence,
		Description: "Query threat intelligence attributes and indicators from MISP",
	}
}

func (p *MISPPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	if u, ok := config["url"].(string); ok {
		p.baseURL = u
	}
	if key, ok := config["auth_key"].(string); ok {
		p.authKey = key
	}
	return nil
}

func (p *MISPPlugin) Close() error {
	return nil
}

func (p *MISPPlugin) LookupIOC(ctx context.Context, iocType string, value string) (map[string]interface{}, error) {
	if p.baseURL == "" {
		return map[string]interface{}{
			"status":   "simulated",
			"ioc_type": iocType,
			"value":    value,
			"matches":  0,
		}, nil
	}

	url := fmt.Sprintf("%s/attributes/restSearch", p.baseURL)
	searchBody := map[string]interface{}{
		"returnFormat": "json",
		"value":        value,
		"type":         iocType,
		"limit":        10,
	}

	data, err := json.Marshal(searchBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", p.authKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("misp query failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

var _ plugins.IntelligencePlugin = (*MISPPlugin)(nil)
