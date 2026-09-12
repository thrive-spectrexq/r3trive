//go:build windows

package windows

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestWindowsServiceSensorLifecycle(t *testing.T) {
	s := NewServiceSensor()
	if s.Name() != "windows_service_sensor" {
		t.Fatalf("unexpected name: %s", s.Name())
	}
	if s.Type() != "service" {
		t.Fatalf("unexpected type: %s", s.Type())
	}

	platforms := s.Platform()
	if len(platforms) != 1 || platforms[0] != sensor.PlatformWindows {
		t.Fatalf("unexpected platforms: %v", platforms)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	eventCh := make(chan event.Event, 10)
	errCh := make(chan error, 1)

	go func() {
		errCh <- s.Start(ctx, eventCh)
	}()

	// Wait for sensor to snapshot baseline and context to cancel
	<-ctx.Done()

	if err := <-errCh; err != nil {
		t.Fatalf("sensor Start returned error: %v", err)
	}

	health := s.Health()
	if !health.Healthy {
		t.Fatalf("expected healthy sensor, got: %v", health)
	}
}
