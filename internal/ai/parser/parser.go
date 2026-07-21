package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

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

// ExtractYAML Code Block extracts YAML content from markdown code fences.
func ExtractYAMLBlock(input string) string {
	if strings.Contains(input, "```yaml") {
		parts := strings.Split(input, "```yaml")
		if len(parts) > 1 {
			sub := strings.Split(parts[1], "```")
			return strings.TrimSpace(sub[0])
		}
	} else if strings.Contains(input, "```") {
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
