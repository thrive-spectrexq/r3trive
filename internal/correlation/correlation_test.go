package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestCorrelationEngine(t *testing.T) {
	engine := New()

	rule := Rule{
		ID:          "rule-001",
		Name:        "Suspicious Process Execution",
		Description: "Detects cmd.exe execution with powershell",
		Severity:    "high",
		Confidence:  0.9,
		Conditions: []Condition{
			{
				Field:    "data.process.name",
				Operator: "eq",
				Value:    "powershell.exe",
			},
		},
		ATTACKTactic:    "Execution",
		ATTACKTechnique: "T1059",
	}

	engine.LoadRules([]Rule{rule})

	evt := event.Event{
		ID:        "evt-100",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Severity:  event.SeverityLow,
		Sensor:    "win_etw",
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     1234,
				Name:    "powershell.exe",
				CmdLine: "powershell.exe -enc AAAA",
			},
		},
	}

	alerts := engine.Evaluate(context.Background(), evt)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	if alerts[0].RuleID != "rule-001" {
		t.Errorf("expected rule ID 'rule-001', got %s", alerts[0].RuleID)
	}

	if alerts[0].Severity != event.SeverityHigh {
		t.Errorf("expected alert severity high, got %s", alerts[0].Severity)
	}
}

func TestThresholdRuleCorrelation(t *testing.T) {
	engine := New()

	rule := Rule{
		ID:          "rule-002",
		Name:        "Brute Force Process Spawn",
		Description: "Spawns 3 processes in window",
		Severity:    "critical",
		Confidence:  0.8,
		Threshold:   3,
		Timeframe:   "1m",
		Conditions: []Condition{
			{
				Field:    "data.process.name",
				Operator: "eq",
				Value:    "cmd.exe",
			},
		},
	}

	engine.LoadRules([]Rule{rule})

	makeEvt := func(id string) event.Event {
		return event.Event{
			ID:        id,
			Timestamp: time.Now().UTC(),
			Type:      event.ProcessCreate,
			Data: event.EventData{
				Process: &event.ProcessData{
					PID:  500,
					Name: "cmd.exe",
				},
			},
		}
	}

	alerts1 := engine.Evaluate(context.Background(), makeEvt("e1"))
	if len(alerts1) != 0 {
		t.Errorf("expected 0 alerts after 1st event, got %d", len(alerts1))
	}

	alerts2 := engine.Evaluate(context.Background(), makeEvt("e2"))
	if len(alerts2) != 0 {
		t.Errorf("expected 0 alerts after 2nd event, got %d", len(alerts2))
	}

	alerts3 := engine.Evaluate(context.Background(), makeEvt("e3"))
	if len(alerts3) != 1 {
		t.Fatalf("expected 1 alert after 3rd event, got %d", len(alerts3))
	}
}
