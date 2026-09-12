package telemetry

import (
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
