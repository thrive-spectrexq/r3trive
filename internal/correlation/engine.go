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

	"github.com/thrive-spectrexq/r3trive/internal/telemetry"
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
	start := time.Now()
	e.mu.Lock()
	defer func() {
		e.mu.Unlock()
		telemetry.RecordCorrelationLatency(ctx, float64(time.Since(start).Milliseconds()))
	}()

	var alerts []event.Alert

	for _, rule := range e.rules {
		if matched := e.matchRule(rule, evt); matched {
			trigger := false

			if rule.Threshold > 1 && rule.Timeframe != "" {
				// Temporal logic partitioned by entity to prevent cross-host alert contamination
				stateKey := rule.ID
				if evt.Host.ID != "" {
					stateKey = rule.ID + ":" + evt.Host.ID
				}

				duration, err := time.ParseDuration(rule.Timeframe)
				if err != nil {
					slog.Warn("invalid timeframe in rule", "rule", rule.ID, "timeframe", rule.Timeframe)
					duration = 5 * time.Minute
				}

				e.state[stateKey] = append(e.state[stateKey], evt)

				// Prune old events
				cutoff := evt.Timestamp.Add(-duration)
				var valid []event.Event
				for _, stored := range e.state[stateKey] {
					if stored.Timestamp.After(cutoff) || stored.Timestamp.Equal(cutoff) {
						valid = append(valid, stored)
					}
				}
				e.state[stateKey] = valid

				if len(e.state[stateKey]) >= rule.Threshold {
					trigger = true
					// Reset state after triggering
					e.state[stateKey] = nil
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

	if len(alerts) > 0 {
		telemetry.RecordAlert(ctx, int64(len(alerts)))
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
	case "ne":
		return value != cond.Value
	case "contains":
		return containsStr(value, cond.Value)
	case "not_contains":
		return !containsStr(value, cond.Value)
	case "startsWith", "startswith":
		return strings.HasPrefix(value, cond.Value)
	case "endsWith", "endswith":
		return strings.HasSuffix(value, cond.Value)
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
// using an optimized zero-reflection fast path for common fields,
// falling back to reflection only for dynamic custom fields.
func extractField(field string, evt event.Event) string {
	if val, ok := fastExtractField(field, &evt); ok {
		return val
	}

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

// fastExtractField provides a fast, zero-reflection accessor for standard schema fields.
func fastExtractField(field string, evt *event.Event) (string, bool) {
	switch strings.ToLower(field) {
	case "type", "event.type":
		return string(evt.Type), true
	case "severity", "event.severity":
		return string(evt.Severity), true
	case "sensor", "event.sensor":
		return evt.Sensor, true
	case "host.id":
		return evt.Host.ID, true
	case "host.hostname":
		return evt.Host.Hostname, true
	case "host.os":
		return evt.Host.OS, true
	case "host.os_version":
		return evt.Host.OSVersion, true
	case "data.process.name", "process.name":
		if evt.Data.Process != nil {
			return evt.Data.Process.Name, true
		}
		return "", true
	case "data.process.path", "process.path":
		if evt.Data.Process != nil {
			return evt.Data.Process.Path, true
		}
		return "", true
	case "data.process.pid", "process.pid":
		if evt.Data.Process != nil {
			return fmt.Sprintf("%d", evt.Data.Process.PID), true
		}
		return "", true
	case "data.process.cmdline", "process.cmdline":
		if evt.Data.Process != nil {
			return evt.Data.Process.CmdLine, true
		}
		return "", true
	case "data.process.user", "process.user":
		if evt.Data.Process != nil {
			return evt.Data.Process.User, true
		}
		return "", true
	case "data.process.parent.name", "data.process.parent_name", "process.parent.name":
		if evt.Data.Process != nil && evt.Data.Process.Parent != nil {
			return evt.Data.Process.Parent.Name, true
		}
		return "", true
	case "data.file.path", "file.path":
		if evt.Data.File != nil {
			return evt.Data.File.Path, true
		}
		return "", true
	case "data.file.name", "file.name":
		if evt.Data.File != nil {
			return evt.Data.File.Name, true
		}
		return "", true
	case "data.file.extension", "file.extension":
		if evt.Data.File != nil {
			return evt.Data.File.Extension, true
		}
		return "", true
	case "data.network.dst_ip", "network.dst_ip":
		if evt.Data.Network != nil {
			return evt.Data.Network.DstIP, true
		}
		return "", true
	case "data.network.src_ip", "network.src_ip":
		if evt.Data.Network != nil {
			return evt.Data.Network.SrcIP, true
		}
		return "", true
	case "data.network.dst_port", "network.dst_port":
		if evt.Data.Network != nil {
			return fmt.Sprintf("%d", evt.Data.Network.DstPort), true
		}
		return "", true
	case "data.network.protocol", "network.protocol":
		if evt.Data.Network != nil {
			return evt.Data.Network.Protocol, true
		}
		return "", true
	case "data.registry.key", "registry.key":
		if evt.Data.Registry != nil {
			return evt.Data.Registry.Key, true
		}
		return "", true
	case "data.registry.value_name", "registry.value_name":
		if evt.Data.Registry != nil {
			return evt.Data.Registry.ValueName, true
		}
		return "", true
	}
	return "", false
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
