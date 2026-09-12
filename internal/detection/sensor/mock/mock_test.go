package mock

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestMockProcessSensor(t *testing.T) {
	s := NewProcessSensor()
	if s.Name() != "MockProcessSensor" {
		t.Errorf("expected name MockProcessSensor, got %s", s.Name())
	}
	if len(s.Platform()) != 3 {
		t.Errorf("expected 3 supported platforms, got %d", len(s.Platform()))
	}

	ch := make(chan event.Event, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = s.Start(ctx, ch)
	}()

	// Verify Stop does not error
	if err := s.Stop(); err != nil {
		t.Errorf("expected nil error on Stop, got %v", err)
	}

	health := s.Health()
	if !health.Healthy {
		t.Error("expected sensor health to be true")
	}

	cancel()
}

func TestMockNetworkSensor(t *testing.T) {
	s := NewNetworkSensor()
	if s.Name() != "MockNetworkSensor" {
		t.Errorf("expected name MockNetworkSensor, got %s", s.Name())
	}

	ch := make(chan event.Event, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = s.Start(ctx, ch)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	if err := s.Stop(); err != nil {
		t.Errorf("expected nil error on Stop, got %v", err)
	}

	health := s.Health()
	if !health.Healthy {
		t.Error("expected network sensor health to be true")
	}
}
