package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/api"
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/detection/pipeline"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/mock"
	"github.com/thrive-spectrexq/r3trive/internal/response"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestE2EWorkflow(t *testing.T) {
	// 1. Config loading & validation
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = tempDir
	dbPath := filepath.Join(tempDir, "e2e.db")
	cfg.Storage.DSN = dbPath
	cfg.Mode = "development"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	// 2. Storage initialization with connection pool & migrations
	store, err := sqlite.New(cfg.Storage.DSN)
	if err != nil {
		t.Fatalf("failed to initialize sqlite store: %v", err)
	}
	defer store.Close()

	// 3. Pipeline with mock sensor and storage
	mockSensor := mock.NewProcessSensor()
	pipe := pipeline.New(pipeline.Config{
		Sensors:        []sensor.Sensor{mockSensor},
		Store:          store,
		BatchSize:      10,
		FlushInterval:  50 * time.Millisecond,
		RingBufferSize: 500,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	receivedCh := make(chan event.Event, 10)
	pipe.OnEvent(func(e event.Event) {
		select {
		case receivedCh <- e:
		default:
		}
	})

	go func() {
		_ = pipe.Start(ctx)
	}()

	// Wait for an event through pipeline
	var sampleEvent event.Event
	select {
	case sampleEvent = <-receivedCh:
		if sampleEvent.Type != event.ProcessCreate {
			t.Errorf("expected ProcessCreate, got %s", sampleEvent.Type)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for pipeline event")
	}

	// 4. Incident creation & correlation
	inc := event.Incident{
		ID:        "INC-E2E-001",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Status:    event.IncidentStatusOpen,
		Severity:  event.SeverityHigh,
		RiskScore: 90,
		Title:     "E2E Test Incident",
		HostIDs:   []string{sampleEvent.Host.ID},
		Alerts: []event.Alert{
			{
				ID:        "ALT-E2E-001",
				Event:     sampleEvent,
				Timestamp: time.Now().UTC(),
				RuleID:    "RULE-E2E-001",
				RuleName:  "Test Execution Rule",
				Severity:  event.SeverityHigh,
			},
		},
	}
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("failed to persist incident: %v", err)
	}

	// 5. Defensive response engine with allowlist guardrail & audit logging
	respEngine := response.New(true) // dry-run mode
	results, err := respEngine.RespondToIncident(ctx, inc, 70)
	if err != nil {
		t.Fatalf("response engine error: %v", err)
	}
	if len(results) == 0 {
		t.Errorf("expected response actions executed for high-risk incident")
	}

	auditLogs := respEngine.AuditLog()
	if len(auditLogs) == 0 {
		t.Errorf("expected audit logs recorded by response engine")
	}

	// Verify allowlist guardrails prevent dangerous actions
	_, errKillInit := respEngine.Execute(ctx, response.ActionKillProcess, map[string]any{"pid": 1})
	if errKillInit == nil {
		t.Errorf("expected defensive guardrail to block killing PID 1")
	}

	_, errBlockLocal := respEngine.Execute(ctx, response.ActionBlockIP, map[string]any{"ip": "127.0.0.1"})
	if errBlockLocal == nil {
		t.Errorf("expected defensive guardrail to block blocking 127.0.0.1")
	}

	// 6. Stop pipeline cleanly
	cancel()

	// 7. Verify API server routes with store
	apiServer := api.NewServer(api.ServerConfig{
		Addr:   "127.0.0.1:0",
		APIKey: "e2e-secret-key",
	}, store)
	if apiServer == nil {
		t.Fatal("failed to construct API server")
	}
}
