//go:build darwin

package macos

import (
	"context"
	"log/slog"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ProcessSensor implements the macOS process sensor.
type ProcessSensor struct{}

// NewProcessSensor creates a new macOS sensor.
func NewProcessSensor() *ProcessSensor {
	return &ProcessSensor{}
}

func (s *ProcessSensor) Name() string {
	return "macos_process_sensor"
}

func (s *ProcessSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformMacOS}
}

func (s *ProcessSensor) Type() string {
	return "process"
}

func (s *ProcessSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy: true,
		Status:  "operational",
	}
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
