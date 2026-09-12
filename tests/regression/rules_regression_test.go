package regression_test

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/correlation"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestDetectionRulesRegression(t *testing.T) {
	rules := []correlation.Rule{
		{
			ID:          "REG-001",
			Name:        "Suspicious Cmdline",
			Severity:    "high",
			Description: "Detects cmd.exe spawning powershell",
			Conditions: []correlation.Condition{
				{
					Field:    "data.process.name",
					Operator: "eq",
					Value:    "powershell.exe",
				},
				{
					Field:    "data.process.parent.name",
					Operator: "eq",
					Value:    "cmd.exe",
				},
			},
		},
		{
			ID:          "REG-002",
			Name:        "Suspicious Network Connect",
			Severity:    "critical",
			Description: "Detects outbound connection to known malicious port",
			Conditions: []correlation.Condition{
				{
					Field:    "data.network.dst_ip",
					Operator: "contains",
					Value:    "185.220",
				},
			},
		},
	}

	engine := correlation.New()
	engine.LoadRules(rules)

	ctx := context.Background()

	// 1. Matched process event
	procEvt := event.Event{
		ID:        "evt-reg-01",
		Timestamp: time.Now(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				Name: "powershell.exe",
				Parent: &event.ParentProcess{
					Name: "cmd.exe",
				},
			},
		},
	}

	matchedAlerts := engine.Evaluate(ctx, procEvt)
	if len(matchedAlerts) != 1 || matchedAlerts[0].RuleID != "REG-001" {
		t.Fatalf("expected 1 match for REG-001, got: %v", matchedAlerts)
	}

	// 2. Matched network event
	netEvt := event.Event{
		ID:        "evt-reg-02",
		Timestamp: time.Now(),
		Type:      event.NetworkConnect,
		Data: event.EventData{
			Network: &event.NetworkData{
				DstIP: "185.220.101.5",
			},
		},
	}

	netAlerts := engine.Evaluate(ctx, netEvt)
	if len(netAlerts) != 1 || netAlerts[0].RuleID != "REG-002" {
		t.Fatalf("expected 1 match for REG-002, got: %v", netAlerts)
	}
}
