package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestRegexOperator_Match(t *testing.T) {
	engine := New()
	engine.LoadRules([]Rule{{
		ID:       "regex-001",
		Name:     "Encoded PowerShell",
		Severity: "high",
		Conditions: []Condition{{
			Field:    "data.process.cmdline",
			Operator: "regex",
			Value:    `(?i)-enc\s+[A-Za-z0-9+/=]+`,
		}},
	}})

	evt := event.Event{
		ID:        "evt-regex-1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     999,
				Name:    "powershell.exe",
				CmdLine: "powershell.exe -enc AAABBBCCC==",
			},
		},
	}

	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert from regex match, got %d", len(alerts))
	}
	if alerts[0].RuleID != "regex-001" {
		t.Errorf("expected rule ID 'regex-001', got %s", alerts[0].RuleID)
	}
}

func TestRegexOperator_NoMatch(t *testing.T) {
	engine := New()
	engine.LoadRules([]Rule{{
		ID:       "regex-002",
		Name:     "Base64 Argument",
		Severity: "medium",
		Conditions: []Condition{{
			Field:    "data.process.cmdline",
			Operator: "regex",
			Value:    `^base64-payload-[0-9]+$`,
		}},
	}})

	evt := event.Event{
		ID:        "evt-regex-2",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     100,
				Name:    "cmd.exe",
				CmdLine: "cmd.exe /c dir",
			},
		},
	}

	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts from non-matching regex, got %d", len(alerts))
	}
}

func TestRegexOperator_InvalidPattern(t *testing.T) {
	engine := New()
	engine.LoadRules([]Rule{{
		ID:       "regex-003",
		Name:     "Bad Regex",
		Severity: "low",
		Conditions: []Condition{{
			Field:    "data.process.name",
			Operator: "regex",
			Value:    `[invalid(`,
		}},
	}})

	evt := event.Event{
		ID:        "evt-regex-3",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:  101,
				Name: "foo.exe",
			},
		},
	}

	// Should NOT panic, should return 0 alerts and log a warning
	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts from invalid regex, got %d", len(alerts))
	}
}

func TestContainsOperator(t *testing.T) {
	engine := New()
	engine.LoadRules([]Rule{{
		ID:       "contains-001",
		Name:     "Contains Test",
		Severity: "medium",
		Conditions: []Condition{{
			Field:    "data.process.cmdline",
			Operator: "contains",
			Value:    "Invoke-Mimikatz",
		}},
	}})

	evt := event.Event{
		ID:        "evt-c1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     200,
				Name:    "powershell.exe",
				CmdLine: "powershell.exe -c Invoke-Mimikatz -DumpCreds",
			},
		},
	}

	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert from contains match, got %d", len(alerts))
	}
}

func TestOneOfOperator(t *testing.T) {
	engine := New()
	engine.LoadRules([]Rule{{
		ID:       "oneof-001",
		Name:     "Known Suspicious Tools",
		Severity: "high",
		Conditions: []Condition{{
			Field:    "data.process.name",
			Operator: "oneOf",
			Values:   []string{"mimikatz.exe", "rubeus.exe", "bloodhound.exe"},
		}},
	}})

	// Should match
	evt := event.Event{
		ID:        "evt-o1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{PID: 300, Name: "rubeus.exe"},
		},
	}
	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for oneOf match, got %d", len(alerts))
	}

	// Should not match
	evt2 := event.Event{
		ID:        "evt-o2",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{PID: 301, Name: "notepad.exe"},
		},
	}
	alerts2 := engine.Evaluate(context.Background(), evt2)
	if len(alerts2) != 0 {
		t.Fatalf("expected 0 alerts for oneOf non-match, got %d", len(alerts2))
	}
}

func TestUnknownOperator(t *testing.T) {
	engine := New()
	engine.LoadRules([]Rule{{
		ID:       "unknown-001",
		Name:     "Bad Operator",
		Severity: "low",
		Conditions: []Condition{{
			Field:    "data.process.name",
			Operator: "notExist",
			Value:    "test",
		}},
	}})

	evt := event.Event{
		ID:        "evt-u1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{PID: 400, Name: "test"},
		},
	}

	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for unknown operator, got %d", len(alerts))
	}
}

func TestEmptyConditions(t *testing.T) {
	engine := New()
	engine.LoadRules([]Rule{{
		ID:         "empty-001",
		Name:       "No Conditions",
		Severity:   "low",
		Conditions: []Condition{},
	}})

	evt := event.Event{
		ID:        "evt-e1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{PID: 500, Name: "anything.exe"},
		},
	}

	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for empty conditions, got %d", len(alerts))
	}
}

func TestExtractField_ReflectionPaths(t *testing.T) {
	evt := event.Event{
		ID:       "evt-ref",
		Type:     event.ProcessCreate,
		Severity: event.SeverityHigh,
		Sensor:   "test_sensor",
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     1234,
				Name:    "evil.exe",
				Path:    "C:\\Windows\\evil.exe",
				CmdLine: "evil.exe --flag",
				User:    "SYSTEM",
				Parent:  &event.ParentProcess{PID: 1, Name: "services.exe", Path: "C:\\Windows\\services.exe"},
			},
			Network: &event.NetworkData{
				DstIP:       "10.0.0.1",
				ProcessName: "evil.exe",
			},
			File:     &event.FileData{Path: "C:\\temp\\payload.dll"},
			Registry: &event.RegistryData{Key: "HKCU\\Run\\evil"},
		},
	}

	tests := []struct {
		field    string
		expected string
	}{
		{"type", "process.create"},
		{"severity", "high"},
		{"sensor", "test_sensor"},
		{"data.process.name", "evil.exe"},
		{"data.process.path", "C:\\Windows\\evil.exe"},
		{"data.process.cmdline", "evil.exe --flag"},
		{"data.process.user", "SYSTEM"},
		{"data.process.parent.name", "services.exe"},
		{"data.network.dst_ip", "10.0.0.1"},
		{"data.network.process_name", "evil.exe"},
		{"data.file.path", "C:\\temp\\payload.dll"},
		{"data.registry.key", "HKCU\\Run\\evil"},
		{"data.nonexistent.field", ""},
		{"totally.bogus", ""},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got := extractField(tt.field, evt)
			if got != tt.expected {
				t.Errorf("extractField(%q) = %q, want %q", tt.field, got, tt.expected)
			}
		})
	}
}

func TestExtractField_NilPointers(t *testing.T) {
	evt := event.Event{
		ID:   "evt-nil",
		Type: event.ProcessCreate,
		Data: event.EventData{}, // All nil pointers
	}

	fields := []string{
		"data.process.name",
		"data.network.dst_ip",
		"data.file.path",
		"data.registry.key",
	}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			got := extractField(field, evt)
			if got != "" {
				t.Errorf("extractField(%q) with nil data = %q, want empty", field, got)
			}
		})
	}
}
