//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/api"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func setupTestServer(t *testing.T) (string, *sqlite.Store, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}

	cfg := api.ServerConfig{
		Addr:   "127.0.0.1:0", // use 127.0.0.1:0 for arbitrary port
		APIKey: "test-secret",
	}

	srv := api.NewServer(cfg, store)
	
	// Start in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Wait for server to start, we'll poll health check or just wait
	time.Sleep(100 * time.Millisecond)

	// We need the actual port. But since we don't have an easy way to get it from srv
	// if it doesn't expose a listener address getter, we might need to rely on standard Addr.
	// Actually, wait, does srv expose the bound port? It doesn't look like it based on server.go.
	// We'll use a specific high port or just assume we can get it from somewhere, wait...
	// Let's modify the Addr to a static port for testing to simplify, or maybe wait...
	// If 127.0.0.1:0 is used, we can't easily discover the port from the outside unless we use net.Listen beforehand.
	// Wait, let's just use a fixed randomish port for the test, e.g., 127.0.0.1:49182
	// I'll rewrite this to a fixed port for simplicity, or we can check what the best approach is.
	// I'll leave it as a high fixed port.
	port := "48192"
	
	// Re-init with fixed port just to be safe
	err = store.Close()
	if err != nil {
		t.Fatalf("failed to close sqlite store: %v", err)
	}
	store, err = sqlite.New(filepath.Join(t.TempDir(), "test2.db"))
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cfg = api.ServerConfig{
		Addr:   "127.0.0.1:" + port,
		APIKey: "test-secret",
	}
	srv = api.NewServer(cfg, store)
	go func() {
		_ = srv.Start()
	}()
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		_ = srv.Stop(context.Background())
		_ = store.Close()
	}

	return "http://127.0.0.1:" + port, store, cleanup
}

func TestAPIHealth(t *testing.T) {
	baseURL, _, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/api/v1/health")
	if err != nil {
		t.Fatalf("GET /api/v1/health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestAPIAuth(t *testing.T) {
	baseURL, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. No API key -> 401
	resp, err := http.Get(baseURL + "/api/v1/events")
	if err != nil {
		t.Fatalf("GET /api/v1/events failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 without API key, got %d", resp.StatusCode)
	}

	// 2. With API key -> 200
	req, _ := http.NewRequest("GET", baseURL+"/api/v1/events", nil)
	req.Header.Set("X-API-Key", "test-secret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/events with auth failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 with API key, got %d", resp2.StatusCode)
	}
}

func TestAPIGetEvents(t *testing.T) {
	baseURL, store, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	// Insert test events
	evt1 := event.Event{
		ID:        "evt-1",
		Timestamp: time.Now(),
		Type:      event.ProcessCreate,
		Severity:  event.SeverityLow,
	}
	evt2 := event.Event{
		ID:        "evt-2",
		Timestamp: time.Now(),
		Type:      event.NetworkConnect,
		Severity:  event.SeverityHigh,
	}
	if err := store.SaveEvents(ctx, []event.Event{evt1, evt2}); err != nil {
		t.Fatalf("failed to insert events: %v", err)
	}

	// GET all events
	req, _ := http.NewRequest("GET", baseURL+"/api/v1/events", nil)
	req.Header.Set("X-API-Key", "test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/events failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var events []event.Event
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}

	// Test filtering
	req, _ = http.NewRequest("GET", baseURL+"/api/v1/events?severity=high", nil)
	req.Header.Set("X-API-Key", "test-secret")
	respFiltered, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/events?severity=high failed: %v", err)
	}
	defer respFiltered.Body.Close()

	var filteredEvents []event.Event
	if err := json.NewDecoder(respFiltered.Body).Decode(&filteredEvents); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(filteredEvents) != 1 {
		t.Errorf("expected 1 high severity event, got %d", len(filteredEvents))
	} else if filteredEvents[0].ID != "evt-2" {
		t.Errorf("expected evt-2, got %s", filteredEvents[0].ID)
	}
}

func TestAPIUpdateIncident(t *testing.T) {
	baseURL, store, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	// Insert incident
	inc := event.Incident{
		ID:        "inc-1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status:    event.IncidentStatusOpen,
		Title:     "Test Incident",
	}
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("failed to insert incident: %v", err)
	}

	// Update status
	updateReq := map[string]string{"status": string(event.IncidentStatusContained)}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", baseURL+"/api/v1/incidents/inc-1/status", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "test-secret")
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT /api/v1/incidents/inc-1/status failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Verify in DB
	updatedInc, err := store.GetIncident(ctx, "inc-1")
	if err != nil {
		t.Fatalf("failed to get updated incident: %v", err)
	}

	if updatedInc.Status != event.IncidentStatusContained {
		t.Errorf("expected status contained, got %s", updatedInc.Status)
	}
}
