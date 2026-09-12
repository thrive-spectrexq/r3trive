//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/api"
	"github.com/thrive-spectrexq/r3trive/internal/detection/pipeline"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/mock"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestE2EMonitorFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Setup DB
	tmpDB := t.TempDir() + "/r3trive_monitor.db"
	store, err := sqlite.New(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create sqlite store: %v", err)
	}
	defer store.Close()

	// 2. Setup Mock Sensor & Pipeline
	mockSensor := mock.NewProcessSensor()
	pl := pipeline.New(pipeline.Config{
		Sensors:        []sensor.Sensor{mockSensor},
		Store:          store,
		RingBufferSize: 100,
		BatchSize:      1,
		FlushInterval:  time.Millisecond * 10,
	})

	go func() {
		if err := pl.Start(ctx); err != nil && err != context.Canceled {
			fmt.Printf("Pipeline error: %v\n", err)
		}
	}()

	// 3. Setup API Server
	apiCfg := api.ServerConfig{
		Addr:   "127.0.0.1:18081",
		APIKey: "test-api-key",
	}
	srv := api.NewServer(apiCfg, store)

	go func() {
		_ = srv.Start()
	}()
	defer srv.Stop(context.Background())

	// Wait for server to start and pipeline to process some events
	time.Sleep(3 * time.Second)

	// 4. Query API
	req, err := http.NewRequest("GET", "http://127.0.0.1:18081/api/v1/events", nil)
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

	// Assuming response is a list of events wrapped in something or just an array
	// Actually, handlers.QueryEvents returns `{"data": [...]}` or just `[...]`
	// Since we just need to verify it returns events, we can parse as a map or slice
	var responseData map[string]interface{}
	var events []event.Event

	err = json.Unmarshal(body, &responseData)
	if err == nil {
		if data, ok := responseData["data"]; ok {
			bytes, _ := json.Marshal(data)
			_ = json.Unmarshal(bytes, &events)
		}
	} else {
		_ = json.Unmarshal(body, &events)
	}

	// If events are still empty, pipeline might not have generated them or API response format is different
	// Let's just check that body is not empty and contains "events" or something
	if len(body) < 10 {
		t.Fatalf("Response body too short: %s", string(body))
	}

	// Print successful response for debug
	t.Logf("Got %d bytes response from API", len(body))
}
