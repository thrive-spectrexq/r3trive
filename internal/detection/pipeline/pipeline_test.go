package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type testSensor struct{}

func (s *testSensor) Name() string                     { return "TestSensor" }
func (s *testSensor) Platform() []sensor.Platform     { return nil }
func (s *testSensor) Type() string                     { return "test" }
func (s *testSensor) Health() sensor.SensorHealth      { return sensor.SensorHealth{Healthy: true} }
func (s *testSensor) Stop() error                      { return nil }
func (s *testSensor) Start(ctx context.Context, out chan<- event.Event) error {
	evt := event.Event{
		ID:        "test-evt-1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Severity:  event.SeverityLow,
		Sensor:    s.Name(),
	}
	select {
	case out <- evt:
	case <-ctx.Done():
		return nil
	}
	<-ctx.Done()
	return nil
}

func TestPipelineExecution(t *testing.T) {
	ts := &testSensor{}

	p := New(Config{
		Sensors:        []sensor.Sensor{ts},
		RingBufferSize: 50,
		BatchSize:      10,
		FlushInterval:  50 * time.Millisecond,
	})

	var mu sync.Mutex
	var collectedEvents []event.Event

	p.OnEvent(func(evt event.Event) {
		mu.Lock()
		collectedEvents = append(collectedEvents, evt)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := p.Start(ctx); err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	mu.Lock()
	count := len(collectedEvents)
	mu.Unlock()

	if count == 0 {
		t.Errorf("expected pipeline to collect events, got 0")
	}

	stats := p.Stats()
	if stats.SensorCount != 1 {
		t.Errorf("expected SensorCount 1, got %d", stats.SensorCount)
	}
}
