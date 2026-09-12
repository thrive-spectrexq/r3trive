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

// JiraPlugin creates security incident tickets in Atlassian Jira.
type JiraPlugin struct {
	jiraURL  string
	username string
	apiToken string
	project  string
	client   *http.Client
}

func NewJiraPlugin() *JiraPlugin {
	return &JiraPlugin{
		project: "SEC",
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *JiraPlugin) Metadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		ID:          "com.r3trive.jira",
		Name:        "Jira Incident Ticketing",
		Version:     "1.0.0",
		APIVersion:  plugins.CurrentAPIVersion,
		Type:        plugins.PluginTypeAction,
		Description: "Create security incident tickets in Atlassian Jira",
	}
}

func (p *JiraPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	if u, ok := config["url"].(string); ok {
		p.jiraURL = u
	}
	if user, ok := config["username"].(string); ok {
		p.username = user
	}
	if token, ok := config["api_token"].(string); ok {
		p.apiToken = token
	}
	if prj, ok := config["project"].(string); ok && prj != "" {
		p.project = prj
	}
	return nil
}

func (p *JiraPlugin) Close() error {
	return nil
}

func (p *JiraPlugin) ExecuteAction(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	if action != "create_ticket" {
		return nil, fmt.Errorf("unsupported action: %s", action)
	}

	title, _ := params["title"].(string)
	description, _ := params["description"].(string)
	if title == "" {
		title = "Security Incident Alert"
	}

	if p.jiraURL == "" {
		// Return simulated ticket ID if unconfigured
		return map[string]interface{}{
			"status":    "simulated",
			"ticket_id": fmt.Sprintf("%s-101", p.project),
			"title":     title,
		}, nil
	}

	body := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{"key": p.project},
			"summary": title,
			"description": map[string]interface{}{
				"type":    "doc",
				"version": 1,
				"content": []map[string]interface{}{
					{
						"type": "paragraph",
						"content": []map[string]string{
							{"type": "text", "text": description},
						},
					},
				},
			},
			"issuetype": map[string]string{"name": "Security Incident"},
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/rest/api/3/issue", p.jiraURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.username, p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create jira ticket: %w", err)
	}
	defer resp.Body.Close()

	return map[string]interface{}{
		"status":     "created",
		"statusCode": resp.StatusCode,
	}, nil
}

var _ plugins.ActionPlugin = (*JiraPlugin)(nil)
