//go:build linux

package linux

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ServiceSensor monitors Linux systemd service units.
type ServiceSensor struct {
	knownUnits      map[string]string // unitName -> activeState
	eventsCollected int64
	mu              sync.RWMutex
	pollInterval    time.Duration
}

// NewServiceSensor creates a new Linux systemd service sensor.
func NewServiceSensor() *ServiceSensor {
	return &ServiceSensor{
		knownUnits:   make(map[string]string),
		pollInterval: 5 * time.Second,
	}
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "operational",
		EventsCollected: atomic.LoadInt64(&s.eventsCollected),
	}
}

func (s *ServiceSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting Linux systemd service sensor")
	s.snapshotBaseline()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.pollServices(ctx, out)
		}
	}
}

func (s *ServiceSensor) Stop() error {
	return nil
}

func (s *ServiceSensor) snapshotBaseline() {
	units := s.queryUnits()
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, state := range units {
		s.knownUnits[name] = state
	}
	slog.Info("Linux service sensor baseline snapshot complete", "units", len(units))
}

func (s *ServiceSensor) pollServices(ctx context.Context, out chan<- event.Event) {
	current := s.queryUnits()

	s.mu.Lock()
	defer s.mu.Unlock()

	for name, state := range current {
		oldState, exists := s.knownUnits[name]
		if !exists {
			s.knownUnits[name] = state
			atomic.AddInt64(&s.eventsCollected, 1)

			evt := event.Event{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				Type:      event.ServiceCreate,
				Severity:  "medium",
				Sensor:    s.Name(),
				Host: event.HostInfo{
					OS: "linux",
				},
				Data: event.EventData{
					Service: &event.ServiceData{
						Name:   name,
						Status: state,
					},
				},
			}

			select {
			case out <- evt:
			case <-ctx.Done():
				return
			}
		} else if oldState != state {
			s.knownUnits[name] = state
			atomic.AddInt64(&s.eventsCollected, 1)

			evtType := event.ServiceStart
			if state == "inactive" || state == "failed" {
				evtType = event.ServiceStop
			}

			evt := event.Event{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				Type:      evtType,
				Severity:  "low",
				Sensor:    s.Name(),
				Host: event.HostInfo{
					OS: "linux",
				},
				Data: event.EventData{
					Service: &event.ServiceData{
						Name:   name,
						Status: state,
					},
				},
			}

			select {
			case out <- evt:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *ServiceSensor) queryUnits() map[string]string {
	results := make(map[string]string)
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return results
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			unit := fields[0]
			active := fields[2]
			if strings.HasSuffix(unit, ".service") {
				results[unit] = active
			}
		}
	}
	return results
}

var _ sensor.Sensor = (*ServiceSensor)(nil)
