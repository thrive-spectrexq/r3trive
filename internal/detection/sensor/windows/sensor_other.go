//go:build !windows

package windows

import (
	"context"
	"fmt"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const (
	NetworkSensorName  = "windows_network_sensor"
	FileSensorName     = "windows_file_sensor"
	RegistrySensorName = "WindowsRegistrySensor"
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

// NetworkSensor is a stub implementation for non-Windows platforms.
type NetworkSensor struct{}

// NewNetworkSensor creates a non-Windows placeholder network sensor.
func NewNetworkSensor() *NetworkSensor {
	return &NetworkSensor{}
}

// NewNetworkSensorWithInterval creates a non-Windows placeholder network sensor.
func NewNetworkSensorWithInterval(interval time.Duration) *NetworkSensor {
	return &NetworkSensor{}
}

// Name returns the sensor identifier.
func (s *NetworkSensor) Name() string {
	return NetworkSensorName
}

// Platform returns the supported platform.
func (s *NetworkSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Type returns the event category.
func (s *NetworkSensor) Type() string {
	return "network"
}

// Health returns current sensor diagnostics.
func (s *NetworkSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy: false,
		Status:  "unsupported on non-windows platform",
	}
}

// Start returns an error on non-Windows platforms.
func (s *NetworkSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	return fmt.Errorf("windows network sensor is not supported on this platform")
}

// Stop performs cleanup.
func (s *NetworkSensor) Stop() error {
	return nil
}

// FileSensor is a stub implementation for non-Windows platforms.
type FileSensor struct{}

// NewFileSensor creates a non-Windows placeholder file sensor.
func NewFileSensor() *FileSensor {
	return &FileSensor{}
}

// NewFileSensorWithPaths creates a non-Windows placeholder file sensor.
func NewFileSensorWithPaths(paths []string, watchSubtree bool) *FileSensor {
	return &FileSensor{}
}

// Name returns the sensor identifier.
func (s *FileSensor) Name() string {
	return FileSensorName
}

// Platform returns the supported platform.
func (s *FileSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Type returns the event category.
func (s *FileSensor) Type() string {
	return "file"
}

// Health returns current sensor diagnostics.
func (s *FileSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy: false,
		Status:  "unsupported on non-windows platform",
	}
}

// Start returns an error on non-Windows platforms.
func (s *FileSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	return fmt.Errorf("windows file sensor is not supported on this platform")
}

// Stop performs cleanup.
func (s *FileSensor) Stop() error {
	return nil
}

// RegistrySensor is a stub implementation for non-Windows platforms.
type RegistrySensor struct{}

// NewRegistrySensor creates a non-Windows placeholder registry sensor.
func NewRegistrySensor() *RegistrySensor {
	return &RegistrySensor{}
}

// Name returns the sensor identifier.
func (s *RegistrySensor) Name() string {
	return RegistrySensorName
}

// Platform returns the supported platform.
func (s *RegistrySensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Type returns the event category.
func (s *RegistrySensor) Type() string {
	return "registry"
}

// Health returns current sensor diagnostics.
func (s *RegistrySensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy: false,
		Status:  "unsupported on non-windows platform",
	}
}

// Start returns an error on non-Windows platforms.
func (s *RegistrySensor) Start(ctx context.Context, ch chan<- event.Event) error {
	return fmt.Errorf("windows registry sensor is not supported on this platform")
}

// Stop performs cleanup.
func (s *RegistrySensor) Stop() error {
	return nil
}

var (
	_ sensor.Sensor = (*ProcessSensor)(nil)
	_ sensor.Sensor = (*NetworkSensor)(nil)
	_ sensor.Sensor = (*FileSensor)(nil)
	_ sensor.Sensor = (*RegistrySensor)(nil)
)
