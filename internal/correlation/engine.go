// Package correlation implements the Correlation Engine, which transforms
// raw event streams into meaningful security incidents by evaluating
// temporal patterns, correlation rules, and MITRE ATT&CK mappings.
//
// See SYSTEM_ARCHITECTURE.md §4.4 for full specification.
package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Engine is the correlation engine that evaluates events against rules
// and produces alerts and incidents.
type Engine struct {
	mu         sync.RWMutex
	rules      []Rule
	state      map[string][]event.Event // Maps RuleID to matched events
	alertCh    chan event.Alert
	regexCache map[string]*regexp.Regexp
}

// Rule represents a behavioral detection rule.
type Rule struct {
	ID          string      `yaml:"id" json:"id"`
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description" json:"description"`
	Severity    string      `yaml:"severity" json:"severity"`
	Confidence  float64     `yaml:"confidence" json:"confidence"`
	Timeframe   string      `yaml:"timeframe,omitempty" json:"timeframe,omitempty"` // e.g., "5m"
	Threshold   int         `yaml:"threshold,omitempty" json:"threshold,omitempty"` // e.g., 5
	Conditions  []Condition `yaml:"conditions" json:"conditions"`

	// ATT&CK mapping
	ATTACKTactic    string `yaml:"attack_tactic" json:"attack_tactic,omitempty"`
	ATTACKTechnique string `yaml:"attack_technique" json:"attack_technique,omitempty"`
}

// Condition represents a single match condition within a rule.
type Condition struct {
	Field    string   `yaml:"field" json:"field"`
	Operator string   `yaml:"operator" json:"operator"` // eq, contains, regex, oneOf
	Value    string   `yaml:"value" json:"value"`
	Values   []string `yaml:"values,omitempty" json:"values,omitempty"` // for oneOf
}

// New creates a new correlation engine.
func New() *Engine {
	return &Engine{
		state:      make(map[string][]event.Event),
		alertCh:    make(chan event.Alert, 100),
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// LoadRules adds detection rules to the engine and precompiles any regex conditions.
func (e *Engine) LoadRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range rules {
		for _, cond := range rule.Conditions {
			if cond.Operator == "regex" && cond.Value != "" {
				if _, exists := e.regexCache[cond.Value]; !exists {
					re, err := regexp.Compile(cond.Value)
					if err != nil {
						slog.Warn("invalid regex pattern in rule condition",
							"rule_id", rule.ID, "pattern", cond.Value, "error", err)
					} else {
						e.regexCache[cond.Value] = re
					}
				}
			}
		}
	}

	e.rules = append(e.rules, rules...)
	slog.Info("correlation rules loaded", "count", len(rules), "total", len(e.rules))
}

// Evaluate checks an event against all loaded rules and returns any alerts.
func (e *Engine) Evaluate(ctx context.Context, evt event.Event) []event.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	var alerts []event.Alert

	for _, rule := range e.rules {
		if matched := e.matchRule(rule, evt); matched {
			trigger := false

			if rule.Threshold > 1 && rule.Timeframe != "" {
				// Temporal logic
				duration, err := time.ParseDuration(rule.Timeframe)
				if err != nil {
					slog.Warn("invalid timeframe in rule", "rule", rule.ID, "timeframe", rule.Timeframe)
					duration = 5 * time.Minute
				}

				e.state[rule.ID] = append(e.state[rule.ID], evt)

				// Prune old events
				cutoff := evt.Timestamp.Add(-duration)
				var valid []event.Event
				for _, stored := range e.state[rule.ID] {
					if stored.Timestamp.After(cutoff) || stored.Timestamp.Equal(cutoff) {
						valid = append(valid, stored)
					}
				}
				e.state[rule.ID] = valid

				if len(e.state[rule.ID]) >= rule.Threshold {
					trigger = true
					// Reset state after triggering
					e.state[rule.ID] = nil
				}
			} else {
				// Immediate trigger
				trigger = true
			}

			if trigger {
				alert := event.Alert{
					ID:              fmt.Sprintf("alert_%d", time.Now().UnixNano()),
					Timestamp:       time.Now().UTC(),
					Event:           evt,
					RuleID:          rule.ID,
					RuleName:        rule.Name,
					Severity:        event.Severity(rule.Severity),
					Confidence:      rule.Confidence,
					RiskScore:       CalculateRiskScore(event.Severity(rule.Severity), rule.Confidence),
					Message:         rule.Description,
					ATTACKTactic:    rule.ATTACKTactic,
					ATTACKTechnique: rule.ATTACKTechnique,
				}
				alerts = append(alerts, alert)

				slog.Info("rule matched",
					"rule_id", rule.ID,
					"rule_name", rule.Name,
					"event_id", evt.ID,
					"severity", rule.Severity,
				)
			}
		}
	}

	return alerts
}

// matchRule evaluates a single rule against an event.
func (e *Engine) matchRule(rule Rule, evt event.Event) bool {
	for _, cond := range rule.Conditions {
		if !e.matchCondition(cond, evt) {
			return false
		}
	}
	return len(rule.Conditions) > 0
}

// matchCondition evaluates a single condition against an event.
func (e *Engine) matchCondition(cond Condition, evt event.Event) bool {
	value := extractField(cond.Field, evt)
	if value == "" {
		return false
	}

	switch cond.Operator {
	case "eq":
		return value == cond.Value
	case "contains":
		return containsStr(value, cond.Value)
	case "oneOf":
		for _, v := range cond.Values {
			if value == v {
				return true
			}
		}
		return false
	case "regex":
		re, ok := e.regexCache[cond.Value]
		if !ok {
			var err error
			re, err = regexp.Compile(cond.Value)
			if err != nil {
				slog.Warn("invalid regex in rule condition",
					"pattern", cond.Value, "error", err)
				return false
			}
			e.regexCache[cond.Value] = re
		}
		return re.MatchString(value)
	default:
		return false
	}
}

// extractField resolves a dotted field path (e.g. "data.process.name")
// by walking the Event struct tree via reflection.
func extractField(field string, evt event.Event) string {
	parts := strings.Split(field, ".")
	v := reflect.ValueOf(evt)

	for _, part := range parts {
		v = resolveStructField(v, part)
		if !v.IsValid() {
			return ""
		}
		// Dereference pointers
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return ""
			}
			v = v.Elem()
		}
	}

	if !v.IsValid() {
		return ""
	}

	return fmt.Sprintf("%v", v.Interface())
}

// resolveStructField finds a struct field by its JSON tag or Go field name (case-insensitive).
func resolveStructField(v reflect.Value, name string) reflect.Value {
	// Dereference pointers first
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return reflect.Value{}
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		// Check JSON tag first
		jsonTag := f.Tag.Get("json")
		if jsonTag != "" {
			tagName := strings.Split(jsonTag, ",")[0]
			if tagName == name {
				return v.Field(i)
			}
		}

		// Fallback to field name (case-insensitive)
		if strings.EqualFold(f.Name, name) {
			return v.Field(i)
		}
	}

	return reflect.Value{}
}

func containsStr(s, substr string) bool {
	return strings.Contains(s, substr)
}
