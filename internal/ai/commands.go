package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Commands provides high-level AI analyst functions.
type Commands struct {
	client  Client
	builder *ContextBuilder
}

// NewCommands initializes the AI commands.
func NewCommands(cfg config.AIConfig) (*Commands, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Commands{
		client:  client,
		builder: &ContextBuilder{},
	}, nil
}

// ExplainEvent uses the AI backend to explain a raw event.
func (c *Commands) ExplainEvent(ctx context.Context, evt event.Event) (string, error) {
	prompt := c.builder.BuildEventContext(evt)
	return c.client.Chat(ctx, prompt)
}

// ExplainAlert uses the AI backend to explain a correlated alert.
func (c *Commands) ExplainAlert(ctx context.Context, alert event.Alert) (string, error) {
	prompt := c.builder.BuildAlertContext(alert)
	return c.client.Chat(ctx, prompt)
}

// ExplainIncident uses the AI backend to explain a correlated incident.
func (c *Commands) ExplainIncident(ctx context.Context, incident event.Incident) (string, error) {
	prompt := c.builder.BuildIncidentContext(incident)
	return c.client.Chat(ctx, prompt)
}

// GenerateRule asks the AI to generate a YAML rule based on a description.
func (c *Commands) GenerateRule(ctx context.Context, description string) (string, error) {
	prompt := fmt.Sprintf(`You are an expert security engineer creating a behavioral detection rule for R3TRIVE.
Our detection engine uses a YAML schema similar to Sigma.
A rule has the following structure:
id: uuid-string
name: string
description: string
severity: low|medium|high|critical
confidence: 0.0-1.0
timeframe: string (optional, e.g. "5m")
threshold: int (optional, default 1)
conditions:
  - field: "data.process.name" (or similar dotted path)
    operator: "eq" (or "contains", "regex", "oneOf")
    value: "cmd.exe"
attack_tactic: string (optional)
attack_technique: string (optional)

Please generate a rule for the following scenario:
%s

Output ONLY the YAML rule. Do not include markdown code blocks or explanations.`, description)

	return c.client.Chat(ctx, prompt)
}

// Summarize asks the AI to summarize an incident or a series of events.
func (c *Commands) Summarize(ctx context.Context, events []event.Event) (string, error) {
	if len(events) == 0 {
		return "No events found in the specified timeframe to summarize.", nil
	}

	var sb strings.Builder
	sb.WriteString("You are an expert security analyst. Please summarize the following sequence of events and identify any potential attack chain:\n\n")
	
	// Limit to last 50 events to avoid token limits
	limit := len(events)
	if limit > 50 {
		limit = 50
	}
	
	for i := 0; i < limit; i++ {
		evt := events[i]
		sb.WriteString(fmt.Sprintf("- [%s] %s (Host: %s, Sensor: %s)\n", evt.Timestamp.Format("15:04:05"), evt.Type, evt.Host.Hostname, evt.Sensor))
	}

	if len(events) > 50 {
		sb.WriteString(fmt.Sprintf("\n... and %d more events omitted for brevity.\n", len(events)-50))
	}

	sb.WriteString("\nProvide a concise executive summary and technical details.")

	return c.client.Chat(ctx, sb.String())
}

// Ask sends a generic question to the AI security assistant.
func (c *Commands) Ask(ctx context.Context, question string) (string, error) {
	prompt := fmt.Sprintf("You are an expert security analyst assisting an incident responder. Answer the following question concisely and technically:\n\n%s", question)
	return c.client.Chat(ctx, prompt)
}
