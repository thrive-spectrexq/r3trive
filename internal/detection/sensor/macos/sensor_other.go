//go:build !darwin

package macos

import (
	"context"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type ProcessSensor struct{}

func NewProcessSensor() *ProcessSensor {
	return &ProcessSensor{}
}

func (s *ProcessSensor) Name() string                { return "macos_process_sensor" }
func (s *ProcessSensor) Platform() []sensor.Platform { return []sensor.Platform{sensor.PlatformMacOS} }
func (s *ProcessSensor) Type() string                { return "process" }
func (s *ProcessSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{Healthy: true, Status: "disabled"}
}
func (s *ProcessSensor) Start(ctx context.Context, out chan<- event.Event) error {
	<-ctx.Done()
	return nil
}
func (s *ProcessSensor) Stop() error { return nil }

type FileSensor struct{}

func NewFileSensor() *FileSensor {
	return &FileSensor{}
}

func (s *FileSensor) Name() string                { return "macos_file_sensor" }
func (s *FileSensor) Platform() []sensor.Platform { return []sensor.Platform{sensor.PlatformMacOS} }
func (s *FileSensor) Type() string                { return "file" }
func (s *FileSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{Healthy: true, Status: "disabled"}
}
func (s *FileSensor) Start(ctx context.Context, out chan<- event.Event) error {
	<-ctx.Done()
	return nil
}
func (s *FileSensor) Stop() error { return nil }

type NetworkSensor struct{}

func NewNetworkSensor() *NetworkSensor {
	return &NetworkSensor{}
}

func (s *NetworkSensor) Name() string                { return "macos_network_sensor" }
func (s *NetworkSensor) Platform() []sensor.Platform { return []sensor.Platform{sensor.PlatformMacOS} }
func (s *NetworkSensor) Type() string                { return "network" }
func (s *NetworkSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{Healthy: true, Status: "disabled"}
}
func (s *NetworkSensor) Start(ctx context.Context, out chan<- event.Event) error {
	<-ctx.Done()
	return nil
}
func (s *NetworkSensor) Stop() error { return nil }

var (
	_ sensor.Sensor = (*ProcessSensor)(nil)
	_ sensor.Sensor = (*FileSensor)(nil)
	_ sensor.Sensor = (*NetworkSensor)(nil)
)
