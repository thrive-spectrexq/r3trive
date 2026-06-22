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
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Engine is the correlation engine that evaluates events against rules
// and produces alerts and incidents.
type Engine struct {
	mu       sync.RWMutex
	rules    []Rule
	state    map[string][]event.Event // Maps RuleID to matched events
	alertCh  chan event.Alert
}

// Rule represents a behavioral detection rule.
type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity" json:"severity"`
	Confidence  float64  `yaml:"confidence" json:"confidence"`
	Timeframe   string   `yaml:"timeframe,omitempty" json:"timeframe,omitempty"` // e.g., "5m"
	Threshold   int      `yaml:"threshold,omitempty" json:"threshold,omitempty"` // e.g., 5
	Conditions  []Condition `yaml:"conditions" json:"conditions"`

	// ATT&CK mapping
	ATTACKTactic    string `yaml:"attack_tactic" json:"attack_tactic,omitempty"`
	ATTACKTechnique string `yaml:"attack_technique" json:"attack_technique,omitempty"`
}

// Condition represents a single match condition within a rule.
type Condition struct {
	Field    string `yaml:"field" json:"field"`
	Operator string `yaml:"operator" json:"operator"` // eq, contains, regex, oneOf
	Value    string `yaml:"value" json:"value"`
	Values   []string `yaml:"values,omitempty" json:"values,omitempty"` // for oneOf
}

// New creates a new correlation engine.
func New() *Engine {
	return &Engine{
		state:   make(map[string][]event.Event),
		alertCh: make(chan event.Alert, 100),
	}
}

// LoadRules adds detection rules to the engine.
func (e *Engine) LoadRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
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
	default:
		return false
	}
}

// extractField retrieves a field value from an event by dotted path.
func extractField(field string, evt event.Event) string {
	switch field {
	case "type":
		return string(evt.Type)
	case "severity":
		return string(evt.Severity)
	case "sensor":
		return evt.Sensor
	case "data.process.name":
		if evt.Data.Process != nil {
			return evt.Data.Process.Name
		}
	case "data.process.path":
		if evt.Data.Process != nil {
			return evt.Data.Process.Path
		}
	case "data.process.cmdline":
		if evt.Data.Process != nil {
			return evt.Data.Process.CmdLine
		}
	case "data.process.user":
		if evt.Data.Process != nil {
			return evt.Data.Process.User
		}
	case "data.process.parent.name":
		if evt.Data.Process != nil && evt.Data.Process.Parent != nil {
			return evt.Data.Process.Parent.Name
		}
	case "data.network.dst_ip":
		if evt.Data.Network != nil {
			return evt.Data.Network.DstIP
		}
	case "data.network.process_name":
		if evt.Data.Network != nil {
			return evt.Data.Network.ProcessName
		}
	case "data.file.path":
		if evt.Data.File != nil {
			return evt.Data.File.Path
		}
	case "data.registry.key":
		if evt.Data.Registry != nil {
			return evt.Data.Registry.Key
		}
	}
	return ""
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
