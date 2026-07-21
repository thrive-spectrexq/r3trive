package rule

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// RuleType defines the rule category (atomic, sequence, aggregate, suppression).
type RuleType string

const (
	TypeAtomic      RuleType = "atomic"
	TypeSequence    RuleType = "sequence"
	TypeAggregate   RuleType = "aggregate"
	TypeSuppression RuleType = "suppression"
)

// Condition defines a single matching criteria.
type Condition struct {
	Field    string   `yaml:"field" json:"field"`
	Operator string   `yaml:"operator" json:"operator"` // eq, ne, contains, startsWith, endsWith, regex, oneOf
	Value    string   `yaml:"value,omitempty" json:"value,omitempty"`
	Values   []string `yaml:"values,omitempty" json:"values,omitempty"`
}

// Rule defines an R3TRIVE YAML detection rule.
type Rule struct {
	ID              string      `yaml:"id" json:"id"`
	Name            string      `yaml:"name" json:"name"`
	Description     string      `yaml:"description" json:"description"`
	Version         string      `yaml:"version,omitempty" json:"version,omitempty"`
	Author          string      `yaml:"author,omitempty" json:"author,omitempty"`
	Type            RuleType    `yaml:"type" json:"type"`
	Severity        string      `yaml:"severity" json:"severity"`
	Confidence      float64     `yaml:"confidence" json:"confidence"`
	Timeframe       string      `yaml:"timeframe,omitempty" json:"timeframe,omitempty"`
	Threshold       int         `yaml:"threshold,omitempty" json:"threshold,omitempty"`
	Conditions      []Condition `yaml:"conditions" json:"conditions"`
	ATTACKTactic    string      `yaml:"attack_tactic,omitempty" json:"attack_tactic,omitempty"`
	ATTACKTechnique string      `yaml:"attack_technique,omitempty" json:"attack_technique,omitempty"`
	Tags            []string    `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// ParseRule unmarshals a YAML byte slice into a Rule.
func ParseRule(data []byte) (*Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing YAML rule: %w", err)
	}
	return &r, nil
}

// ParseRuleFile reads and parses a YAML rule file.
func ParseRuleFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("reading rule file %s: %w", path, err)
	}
	return ParseRule(data)
}

// Validate checks that required fields are present.
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule missing required 'id' field")
	}
	if r.Name == "" {
		return fmt.Errorf("rule missing required 'name' field")
	}
	if len(r.Conditions) == 0 {
		return fmt.Errorf("rule '%s' has no conditions", r.ID)
	}
	return nil
}
