//go:build e2e

package e2e

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/api"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestE2EHuntFlow(t *testing.T) {
	ctx := context.Background()

	// 1. Setup DB
	tmpDB := t.TempDir() + "/r3trive_hunt.db"
	store, err := sqlite.New(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create sqlite store: %v", err)
	}
	defer store.Close()

	// 2. Insert test data
	evt1 := event.Event{
		ID:        "evt-hunt-1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Severity:  event.SeverityHigh,
		Sensor:    "test",
		Host:      event.HostInfo{Hostname: "test-host"},
	}
	evt2 := event.Event{
		ID:        "evt-hunt-2",
		Timestamp: time.Now().UTC(),
		Type:      event.FileCreate,
		Severity:  event.SeverityLow,
		Sensor:    "test",
		Host:      event.HostInfo{Hostname: "test-host"},
	}
	if err := store.SaveEvents(ctx, []event.Event{evt1, evt2}); err != nil {
		t.Fatalf("Failed to insert events: %v", err)
	}

	inc := event.Incident{
		ID:        "inc-hunt-1",
		Title:     "High Severity Process",
		Status:    event.IncidentStatusOpen,
		Severity:  event.SeverityHigh,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("Failed to insert incident: %v", err)
	}

	// 3. Setup API Server
	apiCfg := api.ServerConfig{
		Addr:   "127.0.0.1:18082",
		APIKey: "test-api-key",
	}
	srv := api.NewServer(apiCfg, store)
	
	go func() {
		_ = srv.Start()
	}()
	defer srv.Stop(ctx)

	// Wait for server to start
	time.Sleep(1 * time.Second)

	// 4. Hunt for events with severity=high
	req, err := http.NewRequest("GET", "http://127.0.0.1:18082/api/v1/events?severity=high", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-API-Key", "test-api-key")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	
	if len(body) < 10 {
		t.Fatalf("Response body too short: %s", string(body))
	}

	// 5. Query incidents
	reqInc, err := http.NewRequest("GET", "http://127.0.0.1:18082/api/v1/incidents?status=open", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	reqInc.Header.Set("X-API-Key", "test-api-key")

	respInc, err := client.Do(reqInc)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}
	defer respInc.Body.Close()

	if respInc.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", respInc.StatusCode)
	}
	bodyInc, err := io.ReadAll(respInc.Body)
	if err != nil {
		t.Fatalf("Failed to read incidents body: %v", err)
	}
	if len(bodyInc) < 10 {
		t.Fatalf("Incidents response body too short: %s", string(bodyInc))
	}
}
