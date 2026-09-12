//go:build windows

package windows

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestWindowsProcessSensor_Metadata(t *testing.T) {
	s := NewProcessSensor()

	if s.Name() != "windows_process_sensor" {
		t.Errorf("expected name windows_process_sensor, got %s", s.Name())
	}

	if s.Type() != "process" {
		t.Errorf("expected type process, got %s", s.Type())
	}

	h := s.Health()
	if !h.Healthy {
		t.Errorf("expected initial health to be healthy")
	}

	if err := s.Stop(); err != nil {
		t.Errorf("expected Stop to return nil, got %v", err)
	}
}

func TestWindowsProcessSensor_Lifecycle(t *testing.T) {
	s := NewProcessSensorWithInterval(100 * time.Millisecond)

	ch := make(chan event.Event, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx, ch)
	}()

	// Allow baseline snapshot to initialize
	time.Sleep(200 * time.Millisecond)

	// Spawn a short-lived process to trigger detection
	cmd := exec.Command("cmd.exe", "/c", "echo r3trive-test")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Start()
	_ = cmd.Wait()

	// Wait for sensor run or timeout
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sensor Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sensor did not terminate within timeout")
	}

	// Drain any collected events
	close(ch)
	for range ch {
	}

	h := s.Health()
	if !h.Healthy {
		t.Errorf("expected sensor to remain healthy")
	}
}
