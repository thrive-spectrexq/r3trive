package prompt

import (
	"fmt"
	"strings"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const SystemPersona = `You are a Senior SOC Analyst and Incident Responder specializing in defensive cybersecurity operations.
Your analysis must be technically precise, concise, and prioritized by operational risk.`

// BuildIncidentExplanationPrompt generates a prompt for explaining an incident.
func BuildIncidentExplanationPrompt(inc event.Incident) string {
	var sb strings.Builder
	sb.WriteString(SystemPersona)
	sb.WriteString("\n\nPlease analyze and explain the following security incident:\n\n")
	sb.WriteString(fmt.Sprintf("Incident ID: %s\nTitle: %s\nSeverity: %s\nRisk Score: %d/100\n",
		inc.ID, inc.Title, inc.Severity, inc.RiskScore))

	if len(inc.Alerts) > 0 {
		sb.WriteString("\nCorrelated Alerts:\n")
		for _, a := range inc.Alerts {
			sb.WriteString(fmt.Sprintf("- [%s] Rule: %s (%s) | Tech: %s\n",
				a.Severity, a.RuleName, a.Message, a.ATTACKTechnique))
		}
	}

	sb.WriteString("\nProvide: 1. Executive Summary, 2. Root Cause & Attack Sequence, 3. Recommended Remediation.")
	return sb.String()
}

// BuildRuleGenerationPrompt generates a prompt asking the AI to construct a detection rule.
func BuildRuleGenerationPrompt(description string) string {
	return fmt.Sprintf("%s\n\nGenerate a YAML detection rule for R3TRIVE matching the following scenario:\n%s\n\nOutput only valid YAML.", SystemPersona, description)
}

// BuildAttackChainPrompt generates a prompt for attack chain reconstruction.
func BuildAttackChainPrompt(inc event.Incident) string {
	var sb strings.Builder
	sb.WriteString(SystemPersona)
	sb.WriteString("\n\nReconstruct the multi-stage attack execution chain for Incident ")
	sb.WriteString(inc.ID)
	sb.WriteString(":\n\n")

	for i, alert := range inc.Alerts {
		sb.WriteString(fmt.Sprintf("Stage %d: [%s] %s (Rule: %s, Tech: %s)\n",
			i+1, alert.Severity, alert.Message, alert.RuleName, alert.ATTACKTechnique))
	}

	sb.WriteString("\nOutline the progression from Initial Access -> Execution -> Persistence -> C2.")
	return sb.String()
}
