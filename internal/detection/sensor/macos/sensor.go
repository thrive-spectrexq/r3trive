//go:build darwin

package macos

import (
	"context"
	"log/slog"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ProcessSensor implements the macOS sensor.
type ProcessSensor struct{}

// NewProcessSensor creates a new macOS sensor.
func NewProcessSensor() *ProcessSensor {
	return &ProcessSensor{}
}

func (s *ProcessSensor) Name() string {
	return "macos_process_sensor"
}

func (s *ProcessSensor) Type() string {
	return "process"
}

func (s *ProcessSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting macOS Process Sensor")

	<-ctx.Done()
	return nil
}

func (s *ProcessSensor) Stop() error {
	return nil
}

var _ sensor.Sensor = (*ProcessSensor)(nil)
