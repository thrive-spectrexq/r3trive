package ai

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ContextBuilder constructs prompts and context strings for the AI.
type ContextBuilder struct{}

// BuildEventContext creates a prompt context string for a single event.
func (b *ContextBuilder) BuildEventContext(evt event.Event) string {
	var sb strings.Builder

	sb.WriteString("You are an expert security analyst investigating an endpoint event.\n\n")
	sb.WriteString("Event Details:\n")
	sb.WriteString(fmt.Sprintf("- ID: %s\n", evt.ID))
	sb.WriteString(fmt.Sprintf("- Timestamp: %s\n", evt.Timestamp.String()))
	sb.WriteString(fmt.Sprintf("- Host: %s (%s)\n", evt.Host.Hostname, evt.Host.OS))
	sb.WriteString(fmt.Sprintf("- Type: %s\n", evt.Type))
	sb.WriteString(fmt.Sprintf("- Sensor: %s\n", evt.Sensor))

	data, err := json.MarshalIndent(evt.Data, "", "  ")
	if err == nil {
		sb.WriteString("\nEvent Payload:\n")
		sb.WriteString(string(data))
		sb.WriteString("\n")
	}

	sb.WriteString("\nPlease analyze this event. State if it appears malicious, benign, or suspicious. Provide your reasoning and outline next steps for investigation.")
	
	return sb.String()
}

// BuildAlertContext creates a prompt context string for a correlation alert.
func (b *ContextBuilder) BuildAlertContext(alert event.Alert) string {
	var sb strings.Builder

	sb.WriteString("You are an expert security analyst reviewing an automated detection alert.\n\n")
	sb.WriteString("Alert Details:\n")
	sb.WriteString(fmt.Sprintf("- Rule ID: %s\n", alert.RuleID))
	sb.WriteString(fmt.Sprintf("- Rule Name: %s\n", alert.RuleName))
	sb.WriteString(fmt.Sprintf("- Severity: %s\n", alert.Severity))
	sb.WriteString(fmt.Sprintf("- Message: %s\n", alert.Message))
	sb.WriteString(fmt.Sprintf("- ATT&CK Tactic: %s\n", alert.ATTACKTactic))
	sb.WriteString(fmt.Sprintf("- ATT&CK Technique: %s\n", alert.ATTACKTechnique))

	sb.WriteString("\nTriggering Event:\n")
	data, err := json.MarshalIndent(alert.Event, "", "  ")
	if err == nil {
		sb.WriteString(string(data))
		sb.WriteString("\n")
	}

	sb.WriteString("\nPlease analyze this alert. Explain the potential impact, verify if the event truly matches the rule's intent (handling possible false positives), and recommend remediation actions.")

	return sb.String()
}
