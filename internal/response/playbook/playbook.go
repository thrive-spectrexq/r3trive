package playbook

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ParseYAML decodes a YAML byte slice into a Playbook.
func ParseYAML(data []byte) (*Playbook, error) {
	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("failed to unmarshal playbook YAML: %w", err)
	}

	if err := pb.Validate(); err != nil {
		return nil, fmt.Errorf("playbook validation error: %w", err)
	}

	return &pb, nil
}

// LoadFromFile reads a playbook file from disk and parses it.
func LoadFromFile(filePath string) (*Playbook, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read playbook file %s: %w", filePath, err)
	}

	return ParseYAML(data)
}

// Validate checks that required playbook fields are populated.
func (p *Playbook) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("playbook ID cannot be empty")
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("playbook Name cannot be empty")
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("playbook %s must contain at least one step", p.ID)
	}

	for i, step := range p.Steps {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("step %d in playbook %s is missing a name", i, p.ID)
		}
		if step.Action == "" {
			return fmt.Errorf("step '%s' in playbook %s is missing an action", step.Name, p.ID)
		}
	}

	return nil
}

// Matches evaluates whether an incident meets the playbook trigger criteria.
func (p *Playbook) Matches(incident event.Incident) bool {
	trigger := p.Trigger

	// 1. Incident Type check
	if trigger.IncidentType != "" {
		// match against incident description, title, or alerts
		typeMatched := false
		if strings.Contains(strings.ToLower(incident.Title), strings.ToLower(trigger.IncidentType)) ||
			strings.Contains(strings.ToLower(incident.Description), strings.ToLower(trigger.IncidentType)) {
			typeMatched = true
		} else {
			for _, alert := range incident.Alerts {
				if strings.EqualFold(alert.RuleID, trigger.IncidentType) ||
					strings.Contains(strings.ToLower(alert.RuleName), strings.ToLower(trigger.IncidentType)) {
					typeMatched = true
					break
				}
			}
		}

		if !typeMatched {
			return false
		}
	}

	// 2. Risk Score check
	if trigger.RiskScoreGTE > 0 && incident.RiskScore < trigger.RiskScoreGTE {
		return false
	}

	// 3. Severity check
	if trigger.SeverityGTE != "" && incident.Severity.Weight() < trigger.SeverityGTE.Weight() {
		return false
	}

	// 4. Tags check (if any trigger tag is missing from host or incident, return false)
	if len(trigger.Tags) > 0 {
		tagSet := make(map[string]bool)
		for _, alert := range incident.Alerts {
			for _, t := range alert.Event.Host.Tags {
				tagSet[strings.ToLower(t)] = true
			}
		}
		for _, requiredTag := range trigger.Tags {
			if !tagSet[strings.ToLower(requiredTag)] {
				return false
			}
		}
	}

	return true
}
