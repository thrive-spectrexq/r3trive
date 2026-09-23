package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTelemetryDisabled(t *testing.T) {
	cfg := Config{
		Enabled:  false,
		Endpoint: "localhost:4317",
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("expected nil error when telemetry disabled, got %v", err)
	}

	// Should safely shut down when disabled
	Shutdown()
}

func TestTelemetryRecordersAndPrometheusScrape(t *testing.T) {
	ctx := context.Background()

	RecordEvent(ctx, 10)
	RecordAlert(ctx, 2)
	RecordIncident(ctx, 1)
	RecordDetectionLatency(ctx, 15.5)
	RecordCorrelationLatency(ctx, 4.2)
	RecordAIRequestDuration(ctx, 250.0)
	RecordSensorHealth(ctx, true)

	handler := PrometheusHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "r3trive_events_total") {
		t.Error("expected metrics body to contain r3trive_events_total")
	}
	if !strings.Contains(body, "r3trive_alerts_total") {
		t.Error("expected metrics body to contain r3trive_alerts_total")
	}
	if !strings.Contains(body, "r3trive_incidents_active") {
		t.Error("expected metrics body to contain r3trive_incidents_active")
	}
	if !strings.Contains(body, "r3trive_sensor_health") {
		t.Error("expected metrics body to contain r3trive_sensor_health")
	}
}
