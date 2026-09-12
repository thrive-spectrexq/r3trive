//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/api"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestE2EDefendFlow(t *testing.T) {
	ctx := context.Background()

	// 1. Setup DB
	tmpDB := t.TempDir() + "/r3trive_defend.db"
	store, err := sqlite.New(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create sqlite store: %v", err)
	}
	defer store.Close()

	// 2. Insert test data
	inc := event.Incident{
		ID:        "inc-defend-1",
		Title:     "Critical Ransomware Behavior",
		Status:    event.IncidentStatusOpen,
		Severity:  event.SeverityCritical,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("Failed to insert incident: %v", err)
	}

	// 3. Setup API Server
	apiCfg := api.ServerConfig{
		Addr:   "127.0.0.1:18083",
		APIKey: "test-api-key",
	}
	srv := api.NewServer(apiCfg, store)

	go func() {
		_ = srv.Start()
	}()
	defer srv.Stop(ctx)

	// Wait for server to start
	time.Sleep(1 * time.Second)

	// 4. Update incident status
	payload := map[string]string{"status": string(event.IncidentStatusContained)}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("PUT", "http://127.0.0.1:18083/api/v1/incidents/inc-defend-1/status", bytes.NewBuffer(bodyBytes))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-API-Key", "test-api-key")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// 5. Verify the state was updated properly
	reqGet, err := http.NewRequest("GET", "http://127.0.0.1:18083/api/v1/incidents/inc-defend-1", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	reqGet.Header.Set("X-API-Key", "test-api-key")

	respGet, err := client.Do(reqGet)
	if err != nil {
		t.Fatalf("Failed to execute GET request: %v", err)
	}
	defer respGet.Body.Close()

	if respGet.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 for GET, got %d", respGet.StatusCode)
	}

	bodyInc, _ := io.ReadAll(respGet.Body)
	var updatedInc event.Incident
	if err := json.Unmarshal(bodyInc, &updatedInc); err != nil {
		t.Fatalf("Failed to decode updated incident: %v", err)
	}

	if updatedInc.Status != event.IncidentStatusContained {
		t.Fatalf("Expected incident status to be '%s', got '%s'", event.IncidentStatusContained, updatedInc.Status)
	}
}
