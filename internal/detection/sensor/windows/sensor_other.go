//go:build !windows

package windows

import (
	"context"
	"fmt"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ProcessSensor is a stub implementation for non-Windows platforms.
type ProcessSensor struct{}

// NewProcessSensor creates a non-Windows placeholder process sensor.
func NewProcessSensor() *ProcessSensor {
	return &ProcessSensor{}
}

// NewProcessSensorWithInterval creates a non-Windows placeholder process sensor.
func NewProcessSensorWithInterval(interval time.Duration) *ProcessSensor {
	return &ProcessSensor{}
}

// Name returns the sensor identifier.
func (s *ProcessSensor) Name() string {
	return "windows_process_sensor"
}

// Platform returns the supported platform.
func (s *ProcessSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Type returns the event category.
func (s *ProcessSensor) Type() string {
	return "process"
}

// Health returns current sensor diagnostics.
func (s *ProcessSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy: false,
		Status:  "unsupported on non-windows platform",
	}
}

// Start returns an error on non-Windows platforms.
func (s *ProcessSensor) Start(ctx context.Context, out chan<- event.Event) error {
	return fmt.Errorf("windows process sensor is not supported on this platform")
}

// Stop performs cleanup.
func (s *ProcessSensor) Stop() error {
	return nil
}

var _ sensor.Sensor = (*ProcessSensor)(nil)
