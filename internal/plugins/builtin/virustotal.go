package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/plugins"
)

// VirusTotalPlugin queries hash reputation via VirusTotal v3 API.
type VirusTotalPlugin struct {
	apiKey string
	client *http.Client
}

func NewVirusTotalPlugin() *VirusTotalPlugin {
	return &VirusTotalPlugin{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *VirusTotalPlugin) Metadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		ID:          "com.r3trive.virustotal",
		Name:        "VirusTotal v3 Intelligence",
		Version:     "1.0.0",
		APIVersion:  plugins.CurrentAPIVersion,
		Type:        plugins.PluginTypeIntelligence,
		Description: "Query file hash reputations against VirusTotal threat engine",
	}
}

func (p *VirusTotalPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	if k, ok := config["api_key"].(string); ok {
		p.apiKey = k
	}
	return nil
}

func (p *VirusTotalPlugin) Close() error {
	return nil
}

func (p *VirusTotalPlugin) LookupIOC(ctx context.Context, iocType string, value string) (map[string]interface{}, error) {
	if iocType != "hash" && iocType != "sha256" && iocType != "md5" {
		return nil, fmt.Errorf("unsupported ioc type for virustotal: %s", iocType)
	}

	if p.apiKey == "" {
		// Simulated lookup response when unconfigured
		return map[string]interface{}{
			"status":     "simulated",
			"hash":       value,
			"malicious":  0,
			"suspicious": 0,
			"undetected": 70,
		}, nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", value)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal lookup failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return map[string]interface{}{
			"status":     "not_found",
			"statusCode": resp.StatusCode,
		}, nil
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

var _ plugins.IntelligencePlugin = (*VirusTotalPlugin)(nil)
