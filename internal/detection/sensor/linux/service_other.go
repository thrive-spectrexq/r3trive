//go:build !linux

package linux

import (
	"context"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ServiceSensor stub for non-Linux platforms.
type ServiceSensor struct{}

func NewServiceSensor() *ServiceSensor {
	return &ServiceSensor{}
}

func (s *ServiceSensor) Name() string {
	return "linux_service_sensor"
}

func (s *ServiceSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformLinux}
}

func (s *ServiceSensor) Type() string {
	return "service"
}

func (s *ServiceSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{Healthy: true, Status: "disabled"}
}

func (s *ServiceSensor) Start(ctx context.Context, out chan<- event.Event) error {
	<-ctx.Done()
	return nil
}

func (s *ServiceSensor) Stop() error {
	return nil
}

var _ sensor.Sensor = (*ServiceSensor)(nil)
