package correlation

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestProcessAlert_NewIncident(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_aggregator.db")
	store, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	agg := NewIncidentAggregator(store, AggregatorConfig{
		CorrelateWindow: 10 * time.Minute,
	})

	now := time.Now().UTC()
	alert := event.Alert{
		ID:        "alert-1",
		Timestamp: now,
		Event: event.Event{
			ID: "evt-1",
			Host: event.HostInfo{
				ID:       "host-alpha",
				Hostname: "workstation-01",
			},
			Data: event.EventData{
				Process: &event.ProcessData{
					Name: "cmd.exe",
					Path: "C:\\Windows\\System32\\cmd.exe",
				},
			},
		},
		RuleID:          "rule-cmd",
		RuleName:        "Suspicious CMD Launch",
		Severity:        event.SeverityMedium,
		Confidence:      0.8,
		RiskScore:       20,
		Message:         "cmd.exe spawned unexpectedly",
		ATTACKTactic:    "Execution",
		ATTACKTechnique: "T1059.003",
	}

	inc, err := agg.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inc == nil {
		t.Fatal("expected non-nil incident")
	}

	if inc.ID == "" {
		t.Fatal("expected generated incident ID")
	}

	if inc.Severity != event.SeverityMedium {
		t.Fatalf("expected severity %s, got %s", event.SeverityMedium, inc.Severity)
	}

	if len(inc.Alerts) != 1 {
		t.Fatalf("expected 1 alert in incident, got %d", len(inc.Alerts))
	}

	if len(inc.ArtifactPaths) != 1 || inc.ArtifactPaths[0] != "C:\\Windows\\System32\\cmd.exe" {
		t.Fatalf("unexpected artifact paths: %v", inc.ArtifactPaths)
	}

	// Verify persistence in SQLite
	persisted, err := store.GetIncident(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("failed to query persisted incident: %v", err)
	}

	if persisted.ID != inc.ID {
		t.Fatalf("expected incident ID %s, got %s", inc.ID, persisted.ID)
	}
}

func TestProcessAlert_CorrelateIntoExisting(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_correlate.db")
	store, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	agg := NewIncidentAggregator(store, AggregatorConfig{
		CorrelateWindow: 15 * time.Minute,
	})

	t1 := time.Now().UTC()
	alert1 := event.Alert{
		ID:        "alert-1",
		Timestamp: t1,
		Event: event.Event{
			ID: "evt-1",
			Host: event.HostInfo{
				ID: "host-prod-1",
			},
			Data: event.EventData{
				Process: &event.ProcessData{
					Name: "powershell.exe",
					Path: "C:\\Windows\\System32\\powershell.exe",
				},
			},
		},
		RuleID:          "rule-ps",
		RuleName:        "PowerShell Execution",
		Severity:        event.SeverityLow,
		Confidence:      0.6,
		RiskScore:       10,
		Message:         "PowerShell started",
		ATTACKTactic:    "Execution",
		ATTACKTechnique: "T1059",
	}

	inc1, err := agg.ProcessAlert(context.Background(), alert1)
	if err != nil {
		t.Fatalf("unexpected error alert 1: %v", err)
	}

	t2 := t1.Add(2 * time.Minute)
	alert2 := event.Alert{
		ID:        "alert-2",
		Timestamp: t2,
		Event: event.Event{
			ID: "evt-2",
			Host: event.HostInfo{
				ID: "host-prod-1",
			},
			Data: event.EventData{
				File: &event.FileData{
					Path: "C:\\Users\\Public\\malware.exe",
				},
			},
		},
		RuleID:          "rule-drop",
		RuleName:        "Suspicious File Dropped",
		Severity:        event.SeverityCritical,
		Confidence:      0.95,
		RiskScore:       85,
		Message:         "Executable dropped in Public folder",
		ATTACKTactic:    "DefenseEvasion",
		ATTACKTechnique: "T1036",
	}

	inc2, err := agg.ProcessAlert(context.Background(), alert2)
	if err != nil {
		t.Fatalf("unexpected error alert 2: %v", err)
	}

	// Should be the same incident ID
	if inc1.ID != inc2.ID {
		t.Fatalf("expected same incident ID, got %s and %s", inc1.ID, inc2.ID)
	}

	// Severity escalated to Critical
	if inc2.Severity != event.SeverityCritical {
		t.Fatalf("expected escalated severity critical, got %s", inc2.Severity)
	}

	// 2 alerts correlated
	if len(inc2.Alerts) != 2 {
		t.Fatalf("expected 2 alerts in incident, got %d", len(inc2.Alerts))
	}

	// 2 ATT&CK mappings
	if len(inc2.ATTACKMap) != 2 {
		t.Fatalf("expected 2 ATT&CK mappings, got %d", len(inc2.ATTACKMap))
	}

	// 2 distinct artifact paths
	if len(inc2.ArtifactPaths) != 2 {
		t.Fatalf("expected 2 artifact paths, got %d", len(inc2.ArtifactPaths))
	}

	// Persisted incident check
	persisted, err := store.GetIncident(context.Background(), inc1.ID)
	if err != nil {
		t.Fatalf("failed to query incident from db: %v", err)
	}
	if persisted.Severity != event.SeverityCritical {
		t.Fatalf("expected persisted critical severity, got %s", persisted.Severity)
	}
}

func TestProcessAlert_OutsideWindow(t *testing.T) {
	agg := NewIncidentAggregator(nil, AggregatorConfig{
		CorrelateWindow: 5 * time.Minute,
	})

	t1 := time.Now().UTC().Add(-10 * time.Minute)
	alert1 := event.Alert{
		ID:        "a1",
		Timestamp: t1,
		Event: event.Event{
			Host: event.HostInfo{ID: "host-9"},
		},
		RuleName: "Initial Access",
		Severity: event.SeverityLow,
	}

	inc1, err := agg.ProcessAlert(context.Background(), alert1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t2 := time.Now().UTC()
	alert2 := event.Alert{
		ID:        "a2",
		Timestamp: t2,
		Event: event.Event{
			Host: event.HostInfo{ID: "host-9"},
		},
		RuleName: "Reconnaissance",
		Severity: event.SeverityMedium,
	}

	inc2, err := agg.ProcessAlert(context.Background(), alert2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inc1.ID == inc2.ID {
		t.Fatalf("expected different incident IDs across window expiry, got %s", inc1.ID)
	}
}
