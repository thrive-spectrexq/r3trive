package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestSQLiteStore(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_r3trive.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// 1. Save and Get Event
	evt := event.Event{
		ID:        "evt-test-1",
		Timestamp: time.Now().Truncate(time.Second).UTC(),
		Host: event.HostInfo{
			ID:       "host-1",
			Hostname: "test-host",
			OS:       "linux",
		},
		Type:     event.ProcessCreate,
		Severity: event.SeverityHigh,
		Sensor:   "linux_process_sensor",
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     1234,
				Name:    "malicious_proc",
				CmdLine: "./malicious_proc --arg",
			},
		},
	}

	if err := store.SaveEvent(ctx, evt); err != nil {
		t.Fatalf("failed to save event: %v", err)
	}

	fetchedEvt, err := store.GetEvent(ctx, "evt-test-1")
	if err != nil {
		t.Fatalf("failed to get event: %v", err)
	}

	if fetchedEvt.ID != evt.ID {
		t.Errorf("expected ID %s, got %s", evt.ID, fetchedEvt.ID)
	}
	if fetchedEvt.Data.Process == nil || fetchedEvt.Data.Process.Name != "malicious_proc" {
		t.Errorf("event process data unmarshaled incorrectly")
	}

	// 2. Query Events
	events, err := store.QueryEvents(ctx, storage.EventQuery{
		Severity: string(event.SeverityHigh),
	})
	if err != nil {
		t.Fatalf("failed to query events: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}

	// 3. Save and Get Incident
	inc := event.Incident{
		ID:        "inc-001",
		CreatedAt: time.Now().Truncate(time.Second).UTC(),
		UpdatedAt: time.Now().Truncate(time.Second).UTC(),
		Status:    event.IncidentStatusOpen,
		Severity:  event.SeverityCritical,
		RiskScore: 90,
		Title:     "Critical Malware Detection",
	}

	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("failed to save incident: %v", err)
	}

	fetchedInc, err := store.GetIncident(ctx, "inc-001")
	if err != nil {
		t.Fatalf("failed to get incident: %v", err)
	}
	if fetchedInc.Title != inc.Title {
		t.Errorf("expected incident title %s, got %s", inc.Title, fetchedInc.Title)
	}

	// 4. Update Incident Status
	if err := store.UpdateIncidentStatus(ctx, "inc-001", event.IncidentStatusResolved); err != nil {
		t.Fatalf("failed to update incident status: %v", err)
	}

	incidents, err := store.QueryIncidents(ctx, []event.IncidentStatus{event.IncidentStatusResolved})
	if err != nil {
		t.Fatalf("failed to query incidents: %v", err)
	}
	if len(incidents) != 1 || incidents[0].Status != event.IncidentStatusResolved {
		t.Errorf("expected 1 resolved incident")
	}
}

func TestSQLitePruneEvents(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "prune_test.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	evts := []event.Event{
		{ID: "evt-old-1", Timestamp: now.Add(-48 * time.Hour), Type: event.ProcessCreate, Severity: event.SeverityLow},
		{ID: "evt-old-2", Timestamp: now.Add(-36 * time.Hour), Type: event.NetworkConnect, Severity: event.SeverityLow},
		{ID: "evt-new-1", Timestamp: now.Add(-1 * time.Hour), Type: event.FileModify, Severity: event.SeverityHigh},
	}
	if err := store.SaveEvents(ctx, evts); err != nil {
		t.Fatalf("failed to save events: %v", err)
	}

	cutoff := now.Add(-24 * time.Hour)
	pruned, err := store.PruneEvents(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneEvents error: %v", err)
	}
	if pruned != 2 {
		t.Errorf("expected 2 pruned events, got %d", pruned)
	}

	remaining, err := store.QueryEvents(ctx, storage.EventQuery{Limit: 100})
	if err != nil {
		t.Fatalf("QueryEvents error: %v", err)
	}
	if len(remaining) != 1 || remaining[0].ID != "evt-new-1" {
		t.Errorf("expected 1 remaining event (evt-new-1), got %+v", remaining)
	}
}

func TestSQLiteQueryEventsBounds(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "bounds_test.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	var evts []event.Event
	for i := 0; i < 150; i++ {
		evts = append(evts, event.Event{
			ID:        fmt.Sprintf("evt-%d-%d", now.UnixNano(), i),
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      event.ProcessCreate,
			Severity:  event.SeverityLow,
		})
	}
	if err := store.SaveEvents(ctx, evts); err != nil {
		t.Fatalf("failed to batch save events: %v", err)
	}

	// 1. Default limit when Limit <= 0 should be 100
	results, err := store.QueryEvents(ctx, storage.EventQuery{})
	if err != nil {
		t.Fatalf("QueryEvents default limit error: %v", err)
	}
	if len(results) != 100 {
		t.Errorf("expected default limit to yield 100 events, got %d", len(results))
	}

	// 2. Explicit limit below max
	results120, err := store.QueryEvents(ctx, storage.EventQuery{Limit: 120})
	if err != nil {
		t.Fatalf("QueryEvents limit 120 error: %v", err)
	}
	if len(results120) != 120 {
		t.Errorf("expected 120 events, got %d", len(results120))
	}
}

