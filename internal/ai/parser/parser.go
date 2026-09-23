package parser

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/thrive-spectrexq/r3trive/pkg/rule"
	"gopkg.in/yaml.v3"
)

// IncidentAnalysis holds extracted structured output from an AI incident explanation response.
type IncidentAnalysis struct {
	ExecutiveSummary string   `json:"executive_summary" yaml:"executive_summary"`
	RootCause        string   `json:"root_cause" yaml:"root_cause"`
	RemediationSteps []string `json:"remediation_steps" yaml:"remediation_steps"`
	ConfidenceScore  float64  `json:"confidence_score" yaml:"confidence_score"`
	RiskRating       string   `json:"risk_rating" yaml:"risk_rating"`
}

// ExtractJSON finds and extracts the first JSON block within text.
func ExtractJSON(input string, target any) error {
	start := strings.Index(input, "{")
	end := strings.LastIndex(input, "}")
	if start == -1 || end == -1 || start >= end {
		return fmt.Errorf("no valid JSON object delimiters found in input")
	}

	jsonStr := input[start : end+1]
	if err := json.Unmarshal([]byte(jsonStr), target); err != nil {
		return fmt.Errorf("unmarshalling extracted JSON: %w", err)
	}
	return nil
}

// ExtractYAMLBlock extracts YAML content from markdown code fences.
func ExtractYAMLBlock(input string) string {
	switch {
	case strings.Contains(input, "```yaml"):
		parts := strings.Split(input, "```yaml")
		if len(parts) > 1 {
			sub := strings.Split(parts[1], "```")
			return strings.TrimSpace(sub[0])
		}
	case strings.Contains(input, "```yml"):
		parts := strings.Split(input, "```yml")
		if len(parts) > 1 {
			sub := strings.Split(parts[1], "```")
			return strings.TrimSpace(sub[0])
		}
	case strings.Contains(input, "```"):
		parts := strings.Split(input, "```")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return strings.TrimSpace(input)
}

// ValidateYAML validates that an extracted string is valid YAML.
func ValidateYAML(yamlStr string, target any) error {
	return yaml.Unmarshal([]byte(yamlStr), target)
}

// ParseIncidentAnalysis attempts to extract structured analysis from an AI response.
func ParseIncidentAnalysis(input string) (*IncidentAnalysis, error) {
	var result IncidentAnalysis
	// Try parsing JSON block first
	if err := ExtractJSON(input, &result); err == nil && result.ExecutiveSummary != "" {
		if result.ConfidenceScore == 0 {
			result.ConfidenceScore = ExtractConfidenceScore(input)
		}
		return &result, nil
	}

	// Fallback to text section parsing
	result.ExecutiveSummary = extractSection(input, "Executive Summary", "Root Cause")
	result.RootCause = extractSection(input, "Root Cause", "Remediation")
	remediationText := extractSection(input, "Remediation", "Confidence")

	lines := strings.Split(remediationText, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		l = strings.TrimLeft(l, "*-123456789. ")
		if len(l) > 3 {
			result.RemediationSteps = append(result.RemediationSteps, l)
		}
	}

	result.ConfidenceScore = ExtractConfidenceScore(input)
	if result.ExecutiveSummary == "" {
		result.ExecutiveSummary = strings.TrimSpace(input)
	}

	return &result, nil
}

// ParseRuleResponse parses a generated detection rule from an AI response.
func ParseRuleResponse(input string) (*rule.Rule, error) {
	yamlStr := ExtractYAMLBlock(input)
	parsedRule, err := rule.ParseRule([]byte(yamlStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI generated rule: %w", err)
	}
	if err := parsedRule.Validate(); err != nil {
		return nil, fmt.Errorf("AI generated rule is invalid: %w", err)
	}
	return parsedRule, nil
}

// ExtractConfidenceScore searches text for confidence score indicators.
func ExtractConfidenceScore(input string) float64 {
	rePercent := regexp.MustCompile(`(?i)confidence[:\s]+(\d+)%`)
	if matches := rePercent.FindStringSubmatch(input); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			return float64(val) / 100.0
		}
	}

	reDecimal := regexp.MustCompile(`(?i)confidence[:\s]+(0\.\d+|1\.0)`)
	if matches := reDecimal.FindStringSubmatch(input); len(matches) > 1 {
		if val, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return val
		}
	}

	inputLower := strings.ToLower(input)
	switch {
	case strings.Contains(inputLower, "high confidence"):
		return 0.90
	case strings.Contains(inputLower, "medium confidence"):
		return 0.70
	case strings.Contains(inputLower, "low confidence"):
		return 0.40
	}

	return 0.80 // default reasonable baseline
}

func extractSection(text, startHeader, nextHeader string) string {
	lowerText := strings.ToLower(text)
	lowerStart := strings.ToLower(startHeader)
	idx := strings.Index(lowerText, lowerStart)
	if idx == -1 {
		return ""
	}

	sub := text[idx+len(startHeader):]
	if nextHeader != "" {
		lowerNext := strings.ToLower(nextHeader)
		if nIdx := strings.Index(strings.ToLower(sub), lowerNext); nIdx != -1 {
			sub = sub[:nIdx]
		}
	}

	sub = strings.TrimLeft(sub, ":#-\n\r\t ")
	return strings.TrimSpace(sub)
}

// ActionRecommendation represents a proposed remediation action produced by the AI copilot.
type ActionRecommendation struct {
	Action     string         `json:"action" yaml:"action"`
	Target     string         `json:"target" yaml:"target"`
	Reason     string         `json:"reason" yaml:"reason"`
	Risk       string         `json:"risk" yaml:"risk"`
	Parameters map[string]any `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// ValidateActionRecommendation checks that an action is permitted and has safe, well-formed targets.
func ValidateActionRecommendation(rec ActionRecommendation) error {
	action := strings.ToLower(strings.TrimSpace(rec.Action))
	switch action {
	case "kill_process":
		target := strings.TrimSpace(rec.Target)
		if target == "" {
			if pidVal, ok := rec.Parameters["pid"]; ok {
				target = fmt.Sprintf("%v", pidVal)
			}
		}
		pid, err := strconv.Atoi(target)
		if err != nil || pid <= 1 {
			return fmt.Errorf("kill_process requires valid PID > 1, got %q", target)
		}
	case "block_ip", "unblock_ip":
		target := strings.TrimSpace(rec.Target)
		if target == "" {
			if ipVal, ok := rec.Parameters["ip"]; ok {
				target = fmt.Sprintf("%v", ipVal)
			}
		}
		ip := net.ParseIP(target)
		if ip == nil {
			return fmt.Errorf("%s requires valid IP address, got %q", action, target)
		}
		if ip.IsLoopback() || target == "0.0.0.0" {
			return fmt.Errorf("%s on loopback/wildcard IP is prohibited", action)
		}
	case "isolate_host", "unisolate_host":
		target := strings.TrimSpace(rec.Target)
		if target == "" {
			if hVal, ok := rec.Parameters["host_id"]; ok {
				target = fmt.Sprintf("%v", hVal)
			}
		}
		if target == "" || strings.EqualFold(target, "localhost") || target == "127.0.0.1" {
			return fmt.Errorf("%s target must be a valid non-loopback host identifier", action)
		}
	case "quarantine_file", "unquarantine_file":
		target := strings.TrimSpace(rec.Target)
		if target == "" {
			if pVal, ok := rec.Parameters["path"]; ok {
				target = fmt.Sprintf("%v", pVal)
			}
		}
		cleanTarget := strings.TrimRight(target, "/\\")
		if cleanTarget == "" || cleanTarget == "/" || cleanTarget == "C:" || cleanTarget == `C:\Windows` {
			return fmt.Errorf("%s on root/critical system path is prohibited: %q", action, target)
		}
	default:
		return fmt.Errorf("unrecognized or prohibited defensive action: %q", rec.Action)
	}
	return nil
}

// ParseActionRecommendations parses and validates defensive action recommendations from an AI response.
func ParseActionRecommendations(input string) ([]ActionRecommendation, error) {
	// Attempt JSON array extraction
	start := strings.Index(input, "[")
	end := strings.LastIndex(input, "]")
	if start != -1 && end != -1 && start < end {
		var list []ActionRecommendation
		jsonStr := input[start : end+1]
		if err := json.Unmarshal([]byte(jsonStr), &list); err == nil && len(list) > 0 {
			for i, item := range list {
				if err := ValidateActionRecommendation(item); err != nil {
					return nil, fmt.Errorf("recommendation [%d] validation failed: %w", i, err)
				}
			}
			return list, nil
		}
	}

	// Attempt YAML extraction
	yamlStr := ExtractYAMLBlock(input)
	var yamlList []ActionRecommendation
	if err := yaml.Unmarshal([]byte(yamlStr), &yamlList); err == nil && len(yamlList) > 0 {
		for i, item := range yamlList {
			if err := ValidateActionRecommendation(item); err != nil {
				return nil, fmt.Errorf("recommendation [%d] validation failed: %w", i, err)
			}
		}
		return yamlList, nil
	}

	return nil, fmt.Errorf("failed to parse structured action recommendations from AI response")
}
