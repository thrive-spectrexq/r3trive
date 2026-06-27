package sigma

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Rule represents a parsed Sigma rule.
type Rule struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Status         string                 `yaml:"status"`
	Description    string                 `yaml:"description"`
	Logsource      map[string]string      `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
	Falsepositives []string               `yaml:"falsepositives"`
	Level          string                 `yaml:"level"`
	Tags           []string               `yaml:"tags"`
}

// ParseRule parses a Sigma rule from a byte slice.
func ParseRule(data []byte) (*Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to parse sigma rule: %w", err)
	}
	return &rule, nil
}

// ParseRuleFile parses a Sigma rule from a file.
func ParseRuleFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read sigma rule file: %w", err)
	}
	return ParseRule(data)
}

// Transpiler defines the interface for transpiling Sigma rules to an engine-specific format.
type Transpiler interface {
	// Transpile converts a Sigma rule to a backend-specific format (e.g., Lucene, SQL, or custom R3TRIVE DSL)
	Transpile(rule *Rule) (interface{}, error)
}
