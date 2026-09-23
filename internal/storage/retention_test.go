package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type mockRetentionStore struct {
	events []event.Event
}

func (m *mockRetentionStore) SaveEvent(ctx context.Context, evt event.Event) error { return nil }
func (m *mockRetentionStore) GetEvent(ctx context.Context, id string) (event.Event, error) {
	return event.Event{}, nil
}
func (m *mockRetentionStore) SaveEvents(ctx context.Context, events []event.Event) error { return nil }
func (m *mockRetentionStore) QueryEvents(ctx context.Context, query EventQuery) ([]event.Event, error) {
	if query.Offset >= len(m.events) {
		return nil, nil
	}
	end := len(m.events)
	if query.Limit > 0 && query.Offset+query.Limit < end {
		end = query.Offset + query.Limit
	}
	return m.events[query.Offset:end], nil
}
func (m *mockRetentionStore) SaveAlert(ctx context.Context, alert event.Alert) error { return nil }
func (m *mockRetentionStore) SaveIncident(ctx context.Context, incident event.Incident) error {
	return nil
}
func (m *mockRetentionStore) GetIncident(ctx context.Context, id string) (event.Incident, error) {
	return event.Incident{}, nil
}
func (m *mockRetentionStore) QueryIncidents(ctx context.Context, statuses []event.IncidentStatus) ([]event.Incident, error) {
	return nil, nil
}
func (m *mockRetentionStore) UpdateIncidentStatus(ctx context.Context, id string, status event.IncidentStatus) error {
	return nil
}
func (m *mockRetentionStore) SaveHost(ctx context.Context, host Host) error { return nil }
func (m *mockRetentionStore) GetHost(ctx context.Context, id string) (Host, error) {
	return Host{}, nil
}
func (m *mockRetentionStore) ListHosts(ctx context.Context) ([]Host, error)       { return nil, nil }
func (m *mockRetentionStore) SaveRule(ctx context.Context, rule StoredRule) error { return nil }
func (m *mockRetentionStore) GetRule(ctx context.Context, id string) (StoredRule, error) {
	return StoredRule{}, nil
}
func (m *mockRetentionStore) ListRules(ctx context.Context, enabledOnly bool) ([]StoredRule, error) {
	return nil, nil
}
func (m *mockRetentionStore) DeleteRule(ctx context.Context, id string) error { return nil }
func (m *mockRetentionStore) SaveIOC(ctx context.Context, ioc IOCEntry) error { return nil }
func (m *mockRetentionStore) QueryIOCs(ctx context.Context, iocType string, value string) ([]IOCEntry, error) {
	return nil, nil
}
func (m *mockRetentionStore) PruneEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	count := int64(len(m.events))
	m.events = nil
	return count, nil
}
func (m *mockRetentionStore) Close() error { return nil }

func TestRetentionManager_ExecutePurgeCycle(t *testing.T) {
	tempDir := t.TempDir()
	archiveDir := filepath.Join(tempDir, "archives")

	// 1. Empty events case
	emptyStore := &mockRetentionStore{events: nil}
	mgrEmpty := NewRetentionManager(emptyStore, archiveDir, 24*time.Hour)
	statsEmpty, err := mgrEmpty.ExecutePurgeCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error with empty events: %v", err)
	}
	if statsEmpty.EventsArchived != 0 {
		t.Errorf("expected 0 events archived, got %d", statsEmpty.EventsArchived)
	}

	// 2. Archived events case (1,500 events to verify multi-chunk pagination beyond 1,000)
	var events []event.Event
	for i := 0; i < 1500; i++ {
		events = append(events, event.Event{
			ID:        "evt-old",
			Type:      event.ProcessCreate,
			Timestamp: time.Now().Add(-48 * time.Hour),
		})
	}
	eventsStore := &mockRetentionStore{events: events}
	mgr := NewRetentionManager(eventsStore, archiveDir, 24*time.Hour)
	stats, err := mgr.ExecutePurgeCycle(context.Background())
	if err != nil {
		t.Fatalf("ExecutePurgeCycle error: %v", err)
	}

	if stats.EventsArchived != 1500 {
		t.Errorf("expected 1500 events archived across chunks, got %d", stats.EventsArchived)
	}
	if stats.EventsPurged != 1500 {
		t.Errorf("expected 1500 events purged, got %d", stats.EventsPurged)
	}

	if _, err := os.Stat(stats.ArchiveFile); os.IsNotExist(err) {
		t.Fatalf("expected archive file to exist at %s", stats.ArchiveFile)
	}

	// 3. Background worker test
	ctx, cancel := context.WithCancel(context.Background())
	workerStore := &mockRetentionStore{
		events: []event.Event{
			{ID: "worker-evt", Type: event.ProcessCreate, Timestamp: time.Now().Add(-48 * time.Hour)},
		},
	}
	workerMgr := NewRetentionManager(workerStore, archiveDir, 24*time.Hour)
	ch := workerMgr.StartBackgroundWorker(ctx, 20*time.Millisecond)

	select {
	case st := <-ch:
		if st.EventsArchived != 1 {
			t.Errorf("expected worker to archive 1 event, got %d", st.EventsArchived)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for background worker to produce stats")
	}
	cancel()
}
