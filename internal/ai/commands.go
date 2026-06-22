package ai

import (
	"context"
	"fmt"

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
	prompt := "You are an expert security analyst. Please summarize the following sequence of events and identify any potential attack chain:\n\n"
	for _, evt := range events {
		prompt += fmt.Sprintf("- [%s] %s (Sensor: %s)\n", evt.Timestamp.Format("15:04:05"), evt.Type, evt.Sensor)
	}
	prompt += "\nProvide a concise executive summary and technical details."

	return c.client.Chat(ctx, prompt)
}

// Ask sends a generic question to the AI security assistant.
func (c *Commands) Ask(ctx context.Context, question string) (string, error) {
	prompt := fmt.Sprintf("You are an expert security analyst assisting an incident responder. Answer the following question concisely and technically:\n\n%s", question)
	return c.client.Chat(ctx, prompt)
}
