//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/mock"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestPipelineWithMockSensor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s := mock.NewProcessSensor()

	ch := make(chan event.Event, 10)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx, ch)
	}()

	select {
	case evt := <-ch:
		if evt.Type != event.ProcessCreate {
			t.Errorf("Expected ProcessCreate event, got %q", evt.Type)
		}
	case <-ctx.Done():
		t.Fatal("Timeout waiting for event from mock sensor")
	}

	cancel()
	<-errCh // wait for start to return
}
