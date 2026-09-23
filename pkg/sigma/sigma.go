package sigma

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/pkg/rule"
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
	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("failed to parse sigma rule: %w", err)
	}
	return &r, nil
}

// ParseRuleFile parses a Sigma rule from a file.
func ParseRuleFile(path string) (*Rule, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read sigma rule file: %w", err)
	}
	return ParseRule(data)
}

// Transpiler defines the interface for transpiling Sigma rules to an engine-specific format.
type Transpiler interface {
	Transpile(r *Rule) (*rule.Rule, error)
}

// NativeTranspiler implements Transpiler to convert Sigma rules into R3TRIVE detection rules.
type NativeTranspiler struct{}

// NewTranspiler creates a new Sigma transpiler.
func NewTranspiler() *NativeTranspiler {
	return &NativeTranspiler{}
}

// Transpile converts a parsed Sigma rule into an R3TRIVE detection rule.
func (t *NativeTranspiler) Transpile(sr *Rule) (*rule.Rule, error) {
	if sr == nil {
		return nil, fmt.Errorf("cannot transpile nil sigma rule")
	}

	ruleID := sr.ID
	if ruleID == "" {
		ruleID = fmt.Sprintf("SIGMA-%s", uuid.New().String()[:8])
	}

	severity := strings.ToLower(sr.Level)
	if severity == "" || severity == "informational" {
		severity = "low"
	}

	attackTactic := ""
	attackTechnique := ""
	for _, tag := range sr.Tags {
		tagLower := strings.ToLower(tag)
		if strings.HasPrefix(tagLower, "attack.t") {
			attackTechnique = strings.ToUpper(strings.TrimPrefix(tagLower, "attack."))
		} else if strings.HasPrefix(tagLower, "attack.") {
			attackTactic = strings.TrimPrefix(tagLower, "attack.")
		}
	}

	var conditions []rule.Condition

	for key, val := range sr.Detection {
		if key == "condition" {
			continue
		}

		isFilter := strings.HasPrefix(strings.ToLower(key), "filter")

		switch v := val.(type) {
		case map[string]interface{}:
			for fieldKey, fieldVal := range v {
				conds := parseFieldCondition(fieldKey, fieldVal, isFilter)
				conditions = append(conditions, conds...)
			}
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					for fieldKey, fieldVal := range m {
						conds := parseFieldCondition(fieldKey, fieldVal, isFilter)
						conditions = append(conditions, conds...)
					}
				}
			}
		}
	}

	if len(conditions) == 0 {
		conditions = append(conditions, rule.Condition{
			Field:    "event.type",
			Operator: "eq",
			Value:    "process_create",
		})
	}

	r3Rule := &rule.Rule{
		ID:              ruleID,
		Name:            sr.Title,
		Description:     sr.Description,
		Type:            rule.TypeAtomic,
		Severity:        severity,
		Confidence:      0.85,
		Conditions:      conditions,
		ATTACKTactic:    attackTactic,
		ATTACKTechnique: attackTechnique,
		Tags:            sr.Tags,
	}

	return r3Rule, nil
}

func parseFieldCondition(field string, val interface{}, isNegated bool) []rule.Condition {
	operator := "eq"
	cleanField := field

	if strings.Contains(field, "|") {
		parts := strings.Split(field, "|")
		cleanField = parts[0]
		modifier := parts[len(parts)-1]
		switch modifier {
		case "contains":
			operator = "contains"
		case "startswith":
			operator = "startsWith"
		case "endswith":
			operator = "endsWith"
		case "re", "regex":
			operator = "regex"
		}
	}

	if isNegated {
		switch operator {
		case "eq":
			operator = "ne"
		case "contains":
			operator = "not_contains"
		default:
			operator = "ne"
		}
	}

	targetField := mapSigmaField(cleanField)

	switch v := val.(type) {
	case string:
		return []rule.Condition{
			{
				Field:    targetField,
				Operator: operator,
				Value:    v,
			},
		}
	case []interface{}:
		if isNegated {
			// For negated lists, each item must not match (AND NE)
			var conds []rule.Condition
			for _, item := range v {
				conds = append(conds, rule.Condition{
					Field:    targetField,
					Operator: "ne",
					Value:    fmt.Sprintf("%v", item),
				})
			}
			return conds
		}
		var strVals []string
		for _, item := range v {
			strVals = append(strVals, fmt.Sprintf("%v", item))
		}
		return []rule.Condition{
			{
				Field:    targetField,
				Operator: "oneOf",
				Values:   strVals,
			},
		}
	default:
		return []rule.Condition{
			{
				Field:    targetField,
				Operator: operator,
				Value:    fmt.Sprintf("%v", v),
			},
		}
	}
}

func mapSigmaField(field string) string {
	switch strings.ToLower(field) {
	case "image", "processname", "originalfilename":
		return "data.process.name"
	case "commandline":
		return "data.process.cmdline"
	case "parentimage", "parent_image", "parentprocessname":
		return "data.process.parent.name"
	case "user":
		return "data.process.user"
	case "destinationip", "dst_ip":
		return "data.network.dst_ip"
	case "destinationport", "dst_port":
		return "data.network.dst_port"
	case "targetfilename", "path":
		return "data.file.path"
	default:
		return field
	}
}
