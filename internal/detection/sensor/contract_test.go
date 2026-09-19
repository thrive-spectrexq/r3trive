package sensor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/mock"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// runSensorContractTest verifies that a sensor implementation adheres to the sensor.Sensor interface contract.
func runSensorContractTest(t *testing.T, s sensor.Sensor, maxWait time.Duration) {
	t.Helper()

	// 1. Identity & platform declarations
	name := s.Name()
	if name == "" {
		t.Errorf("sensor Name() must not be empty")
	}

	platforms := s.Platform()
	if len(platforms) == 0 {
		t.Errorf("sensor Platform() must declare at least one supported platform")
	}

	// 2. Initial health check
	initialHealth := s.Health()
	if initialHealth.ErrorCount != 0 {
		t.Errorf("expected initial ErrorCount = 0, got %d", initialHealth.ErrorCount)
	}

	// 3. Lifecycle start, run, and cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan event.Event, 100)
	errChan := make(chan error, 1)

	go func() {
		errChan <- s.Start(ctx, ch)
	}()

	// Check for event emissions or timeout
	select {
	case evt := <-ch:
		if evt.ID == "" {
			t.Errorf("emitted event ID must not be empty")
		}
		if evt.Timestamp.IsZero() {
			t.Errorf("emitted event Timestamp must not be zero")
		}
		if evt.Type == "" {
			t.Errorf("emitted event Type must not be empty")
		}
		if evt.Sensor == "" {
			t.Errorf("emitted event Sensor name must not be empty")
		}
	case <-time.After(maxWait):
		t.Logf("sensor %s did not emit events within %v; proceeding with shutdown verification", name, maxWait)
	}

	// 4. Clean shutdown via cancel & Stop
	cancel()
	if err := s.Stop(); err != nil {
		t.Errorf("sensor Stop() returned unexpected error: %v", err)
	}

	// 5. Verify Start returns cleanly without hanging
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("sensor Start() exited with error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("sensor Start() failed to terminate within 3s after context cancellation")
	}

	// 6. Post-shutdown health inspection
	postHealth := s.Health()
	if postHealth.EventsCollected < 0 {
		t.Errorf("EventsCollected should be non-negative, got %d", postHealth.EventsCollected)
	}
}

func TestSensorContracts(t *testing.T) {
	t.Run("mock_process_sensor", func(t *testing.T) {
		runSensorContractTest(t, mock.NewProcessSensor(), 50*time.Millisecond)
	})

	t.Run("mock_network_sensor", func(t *testing.T) {
		runSensorContractTest(t, mock.NewNetworkSensor(), 50*time.Millisecond)
	})
}
