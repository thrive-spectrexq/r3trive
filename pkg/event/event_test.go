package event

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSeverityWeightsAndExitCodes(t *testing.T) {
	tests := []struct {
		sev      Severity
		weight   int
		exitCode int
	}{
		{SeverityLow, 10, 10},
		{SeverityMedium, 25, 11},
		{SeverityHigh, 50, 12},
		{SeverityCritical, 90, 13},
		{Severity("unknown"), 0, 0},
	}

	for _, tt := range tests {
		if got := tt.sev.Weight(); got != tt.weight {
			t.Errorf("Weight() for %s = %d; want %d", tt.sev, got, tt.weight)
		}
		if got := tt.sev.ExitCode(); got != tt.exitCode {
			t.Errorf("ExitCode() for %s = %d; want %d", tt.sev, got, tt.exitCode)
		}
	}
}

func TestEventSerialization(t *testing.T) {
	now := time.Now()
	evt := Event{
		ID:        "evt-001",
		Timestamp: now,
		Host: HostInfo{
			ID:        "host-1",
			Hostname:  "test-endpoint",
			OS:        "linux",
			OSVersion: "6.5.0",
			Arch:      "amd64",
			Tags:      []string{"prod", "web"},
		},
		Type:     ProcessCreate,
		Severity: SeverityHigh,
		Sensor:   "proc-sensor",
		Data: EventData{
			Process: &ProcessData{
				PID:     1234,
				PPID:    1,
				Name:    "bash",
				Path:    "/bin/bash",
				CmdLine: "bash -c whoami",
				User:    "root",
				Parent: &ParentProcess{
					PID:  1,
					Name: "systemd",
					Path: "/lib/systemd/systemd",
				},
			},
		},
	}

	summary := evt.String()
	if summary != "[high] process.create evt-001 on test-endpoint" {
		t.Errorf("unexpected event String(): %s", summary)
	}

	jsonBytes, err := evt.JSON()
	if err != nil {
		t.Fatalf("evt.JSON() failed: %v", err)
	}

	var unmarshaled Event
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("failed unmarshaling event JSON: %v", err)
	}

	if unmarshaled.ID != evt.ID || unmarshaled.Data.Process.PID != 1234 {
		t.Errorf("unmarshaled event mismatch: %+v", unmarshaled)
	}

	prettyBytes, err := evt.PrettyJSON()
	if err != nil {
		t.Fatalf("evt.PrettyJSON() failed: %v", err)
	}
	if len(prettyBytes) <= len(jsonBytes) {
		t.Errorf("pretty JSON length (%d) should be greater than compact JSON length (%d)", len(prettyBytes), len(jsonBytes))
	}
}

func TestAlertAndIncident(t *testing.T) {
	evt := Event{
		ID:       "evt-alert-1",
		Type:     NetworkConnect,
		Severity: SeverityCritical,
		Host:     HostInfo{Hostname: "workstation-1"},
	}

	alert := Alert{
		ID:              "alt-001",
		Timestamp:       time.Now(),
		Event:           evt,
		RuleID:          "R3T-NET-001",
		RuleName:        "Suspicious Outbound Connect",
		Severity:        SeverityCritical,
		Confidence:      0.95,
		RiskScore:       85,
		Message:         "Detected outbound C2 beacon",
		ATTACKTactic:    "Command and Control",
		ATTACKTechnique: "T1071",
		Acknowledged:    false,
	}

	if alert.RiskScore != 85 || alert.RuleID != "R3T-NET-001" {
		t.Errorf("unexpected alert fields: %+v", alert)
	}

	incident := Incident{
		ID:          "inc-001",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Status:      IncidentStatusOpen,
		Severity:    SeverityCritical,
		RiskScore:   90,
		Title:       "C2 Beaconing Campaign",
		Description: "Multi-stage beaconing detected",
		Alerts:      []Alert{alert},
		HostIDs:     []string{"workstation-1"},
		ATTACKMap: []ATTACKMapping{
			{
				Tactic:    "Command and Control",
				Technique: "T1071",
				Name:      "Application Layer Protocol",
			},
		},
	}

	if incident.Status != IncidentStatusOpen {
		t.Errorf("expected open incident status, got %s", incident.Status)
	}
	if len(incident.Alerts) != 1 {
		t.Errorf("expected 1 alert in incident, got %d", len(incident.Alerts))
	}
}
