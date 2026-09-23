package feeds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thrive-spectrexq/r3trive/internal/intelligence/ioc"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestFeedsManager_FetchAndPersist(t *testing.T) {
	// Setup test server serving sample IOC feed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []ioc.IOCEntry{
			{
				ID:          "feed-ioc-1",
				Type:        ioc.IOCTypeIP,
				Value:       "198.51.100.99",
				Severity:    event.SeverityHigh,
				Description: "Threat feed IP",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()

	// In-memory sqlite store
	tmpDB := t.TempDir() + "/test_feeds.db"
	store, err := sqlite.New(tmpDB)
	if err != nil {
		t.Fatalf("sqlite.New failed: %v", err)
	}
	defer store.Close()

	iocEngine := ioc.NewEngine()
	mgr := NewManager(iocEngine)
	mgr.SetStore(store)

	src := FeedSource{
		ID:     "remote-feed-1",
		Name:   "Test Threat Feed",
		URL:    server.URL,
		Format: "json",
	}

	count, err := mgr.FetchSource(context.Background(), src)
	if err != nil {
		t.Fatalf("FetchSource failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 entry fetched, got %d", count)
	}

	// Verify loaded in memory
	if iocEngine.Count() != 1 {
		t.Errorf("expected 1 IOC in engine, got %d", iocEngine.Count())
	}

	// Verify persisted to store
	storedIOCs, err := store.QueryIOCs(context.Background(), "", "")
	if err != nil {
		t.Fatalf("QueryIOCs failed: %v", err)
	}
	if len(storedIOCs) != 1 {
		t.Fatalf("expected 1 IOC persisted to store, got %d", len(storedIOCs))
	}
	if storedIOCs[0].Value != "198.51.100.99" {
		t.Errorf("expected stored IOC value 198.51.100.99, got %s", storedIOCs[0].Value)
	}

	// Test LoadFromStore into a fresh engine
	freshEngine := ioc.NewEngine()
	freshMgr := NewManager(freshEngine)
	freshMgr.SetStore(store)

	warmedCount, err := freshMgr.LoadFromStore(context.Background())
	if err != nil {
		t.Fatalf("LoadFromStore failed: %v", err)
	}
	if warmedCount != 1 {
		t.Errorf("expected 1 warmed IOC, got %d", warmedCount)
	}
	if freshEngine.Count() != 1 {
		t.Errorf("expected 1 IOC in freshEngine, got %d", freshEngine.Count())
	}
}
