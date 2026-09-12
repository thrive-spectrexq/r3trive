//go:build windows

package windows

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

// ServiceSensor monitors Windows services for status changes and creation.
type ServiceSensor struct {
	knownServices   map[string]string // serviceName -> state (RUNNING, STOPPED, etc.)
	eventsCollected int64
	mu              sync.RWMutex
	hostname        string
	pollInterval    time.Duration
}

// NewServiceSensor creates a new Windows service monitoring sensor.
func NewServiceSensor() *ServiceSensor {
	return &ServiceSensor{
		knownServices: make(map[string]string),
		hostname:      getHostname(),
		pollInterval:  5 * time.Second,
	}
}

func (s *ServiceSensor) Name() string {
	return "windows_service_sensor"
}

func (s *ServiceSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
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

// Start begins periodic polling of Windows services.
func (s *ServiceSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting Windows service sensor")

	// Take baseline snapshot
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

// snapshotBaseline populates knownServices without emitting events.
func (s *ServiceSensor) snapshotBaseline() {
	services := s.queryServices()
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, state := range services {
		s.knownServices[name] = state
	}
	slog.Info("Windows service sensor baseline snapshot complete", "services", len(services))
}

func (s *ServiceSensor) pollServices(ctx context.Context, out chan<- event.Event) {
	current := s.queryServices()

	s.mu.Lock()
	defer s.mu.Unlock()

	for name, state := range current {
		oldState, exists := s.knownServices[name]
		if !exists {
			// Newly created / detected service
			s.knownServices[name] = state
			atomic.AddInt64(&s.eventsCollected, 1)

			evt := event.Event{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				Type:      event.ServiceCreate,
				Severity:  "medium",
				Sensor:    s.Name(),
				Host: event.HostInfo{
					Hostname: s.hostname,
					OS:       "windows",
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
			// State transition (e.g. STOPPED -> RUNNING or RUNNING -> STOPPED)
			s.knownServices[name] = state
			atomic.AddInt64(&s.eventsCollected, 1)

			evtType := event.ServiceStart
			if state == "STOPPED" {
				evtType = event.ServiceStop
			}

			evt := event.Event{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				Type:      evtType,
				Severity:  "low",
				Sensor:    s.Name(),
				Host: event.HostInfo{
					Hostname: s.hostname,
					OS:       "windows",
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

// queryServices parses Windows service status from powershell / sc query.
func (s *ServiceSensor) queryServices() map[string]string {
	results := make(map[string]string)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-Service | Select-Object -Property Name,Status | ForEach-Object { \"$($_.Name):$($_.Status)\" }")
	out, err := cmd.Output()
	if err != nil {
		return results
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			status := strings.ToUpper(strings.TrimSpace(parts[1]))
			if name != "" {
				results[name] = status
			}
		}
	}

	return results
}

var _ sensor.Sensor = (*ServiceSensor)(nil)
