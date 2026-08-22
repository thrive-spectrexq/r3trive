//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func setupTestStore(t *testing.T) storage.Store {
	tmpDir := t.TempDir()
	store, err := sqlite.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Failed to create sqlite store: %v", err)
	}
	return store
}

func TestSQLiteSaveAndGetEvent(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	evt := event.Event{
		ID:        "test-evt-001",
		Timestamp: time.Now().UTC(),
		Host:      event.HostInfo{ID: "host-1", Hostname: "test-host", OS: "linux"},
		Type:      event.ProcessCreate,
		Severity:  event.SeverityHigh,
		Sensor:    "test_sensor",
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:  1234,
				Name: "suspicious.exe",
				Path: "/usr/bin/suspicious.exe",
			},
		},
	}

	if err := store.SaveEvent(ctx, evt); err != nil {
		t.Fatalf("Failed to save event: %v", err)
	}

	got, err := store.GetEvent(ctx, evt.ID)
	if err != nil {
		t.Fatalf("Failed to get event: %v", err)
	}

	if got.ID != evt.ID {
		t.Errorf("Expected ID %q, got %q", evt.ID, got.ID)
	}
}

func TestSQLiteSaveAndQueryEvents(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	events := []event.Event{
		{ID: "evt-1", Type: event.ProcessCreate, Severity: event.SeverityHigh, Timestamp: time.Now().UTC()},
		{ID: "evt-2", Type: event.NetworkConnect, Severity: event.SeverityLow, Timestamp: time.Now().UTC()},
	}

	if err := store.SaveEvents(ctx, events); err != nil {
		t.Fatalf("Failed to save events: %v", err)
	}

	query := storage.EventQuery{
		Type: string(event.ProcessCreate),
	}
	results, err := store.QueryEvents(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 || results[0].ID != "evt-1" {
		t.Errorf("Expected 1 result with ID evt-1, got %d", len(results))
	}
}

func TestSQLiteSaveAlert(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	evt := event.Event{
		ID:        "evt-123",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveEvent(ctx, evt); err != nil {
		t.Fatalf("Failed to save event: %v", err)
	}

	alert := event.Alert{
		ID:              "alert-001",
		Event:           evt,
		Timestamp:       time.Now().UTC(),
		RuleID:          "rule-001",
		RuleName:        "Suspicious Process",
		Severity:        event.SeverityHigh,
		Confidence:      0.95,
		RiskScore:       85,
		Message:         "Suspicious process detected",
		ATTACKTactic:    "Execution",
		ATTACKTechnique: "T1059",
	}

	if err := store.SaveAlert(ctx, alert); err != nil {
		t.Fatalf("Failed to save alert: %v", err)
	}
}

func TestSQLiteIncidentLifecycle(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	incident := event.Incident{
		ID:          "inc-001",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		Status:      event.IncidentStatusOpen,
		Severity:    event.SeverityCritical,
		RiskScore:   94,
		Title:       "Active Threat Detected",
		Description: "Multiple high-severity alerts correlated",
		HostIDs:     []string{"host-1"},
	}

	if err := store.SaveIncident(ctx, incident); err != nil {
		t.Fatalf("Failed to save incident: %v", err)
	}

	got, err := store.GetIncident(ctx, incident.ID)
	if err != nil {
		t.Fatalf("Failed to get incident: %v", err)
	}
	if got.Status != event.IncidentStatusOpen {
		t.Errorf("Expected status %q, got %q", event.IncidentStatusOpen, got.Status)
	}

	if err := store.UpdateIncidentStatus(ctx, incident.ID, event.IncidentStatusContained); err != nil {
		t.Fatalf("Failed to update status: %v", err)
	}

	updated, err := store.GetIncident(ctx, incident.ID)
	if err != nil {
		t.Fatalf("Failed to get updated incident: %v", err)
	}
	if updated.Status != event.IncidentStatusContained {
		t.Errorf("Expected status %q, got %q", event.IncidentStatusContained, updated.Status)
	}
}

func TestSQLiteBatchSaveEvents(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	var events []event.Event
	for i := 0; i < 100; i++ {
		events = append(events, event.Event{
			ID:        "batch-evt", // real system would need distinct IDs, but this tests save batching
			Timestamp: time.Now().UTC(),
		})
	}

	if err := store.SaveEvents(ctx, events); err != nil {
		t.Fatalf("Failed to batch save: %v", err)
	}
}
