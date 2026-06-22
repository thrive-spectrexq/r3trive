package windows

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const (
	KernelProcessProviderGUID = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
	ProcessSensorName         = "WindowsProcessSensor"
)

// ProcessSensor implements the sensor.Sensor interface using ETW.
type ProcessSensor struct {
	session  *etw.RealTimeSession
	consumer *etw.Consumer
	health   sensor.SensorHealth
	mu       sync.RWMutex
	cancel   context.CancelFunc
}

// NewProcessSensor creates a new ETW-based process sensor.
func NewProcessSensor() *ProcessSensor {
	return &ProcessSensor{
		health: sensor.SensorHealth{
			Healthy: true,
			Status:  "Initialized",
		},
	}
}

// Name returns the sensor's unique identifier.
func (s *ProcessSensor) Name() string {
	return ProcessSensorName
}

// Platform returns the supported platforms.
func (s *ProcessSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Health returns the current health status.
func (s *ProcessSensor) Health() sensor.SensorHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.health
}

// updateHealth updates the sensor's health status.
func (s *ProcessSensor) updateHealth(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.health.Healthy = false
		s.health.Status = err.Error()
		s.health.ErrorCount++
	} else {
		s.health.Healthy = true
		s.health.Status = "Running"
		s.health.EventsCollected++
		s.health.LastEventTime = time.Now().UTC().Format(time.RFC3339)
	}
}

// Start begins collecting ETW process events.
func (s *ProcessSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	sessionName := fmt.Sprintf("R3TRIVE-Process-%s", uuid.New().String()[:8])
	session := etw.NewRealTimeSession(sessionName)
	s.session = session

	s.consumer = etw.NewRealTimeConsumer(ctx)
	s.consumer.FromSessions(s.session)

	s.consumer.EventCallback = func(e *etw.Event) error {
		// Event ID 1: ProcessStart, Event ID 2: ProcessStop
		var eventType event.EventType
		if e.System.EventID == 1 {
			eventType = event.ProcessCreate
		} else if e.System.EventID == 2 {
			eventType = event.ProcessExit
		} else {
			return nil
		}

		pid, _ := e.GetProperty("ProcessID")
		ppid, _ := e.GetProperty("ParentProcessID")
		imageName, _ := e.GetProperty("ImageName")
		cmdline, _ := e.GetProperty("CommandLine")

		// Safely extract string values
		path := fmt.Sprintf("%v", imageName)
		name := extractNameFromPath(path)
		cmd := fmt.Sprintf("%v", cmdline)

		// Create the common event
		ev := event.Event{
			ID:        fmt.Sprintf("evt_%s", uuid.New().String()),
			Timestamp: e.System.TimeCreated.SystemTime.UTC(),
			Host: event.HostInfo{
				Hostname: getHostname(),
				OS:       "windows",
			},
			Type:     eventType,
			Severity: event.SeverityLow, // Upgraded by correlation
			Sensor:   s.Name(),
			Data: event.EventData{
				Process: &event.ProcessData{
					PID:     toInt(pid),
					PPID:    toInt(ppid),
					Name:    name,
					Path:    path,
					CmdLine: cmd,
				},
			},
		}

		select {
		case ch <- ev:
			s.updateHealth(nil)
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}

	provider := etw.MustParseProvider(KernelProcessProviderGUID)
	if err := s.session.EnableProvider(provider); err != nil {
		s.updateHealth(err)
		return fmt.Errorf("failed to enable provider: %w", err)
	}

	// Start the session (blocks until stopped)
	go func() {
		err := s.session.Start()
		if err != nil {
			s.updateHealth(err)
		}
	}()

	// Start consumer
	go func() {
		if err := s.consumer.Start(); err != nil {
			s.updateHealth(err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return s.Stop()
}

// Stop stops the ETW session.
func (s *ProcessSensor) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.consumer != nil {
		if err := s.consumer.Stop(); err != nil {
			s.updateHealth(err)
		}
	}
	if s.session != nil {
		if err := s.session.Stop(); err != nil {
			s.updateHealth(err)
			return err
		}
	}
	s.mu.Lock()
	s.health.Healthy = false
	s.health.Status = "Stopped"
	s.mu.Unlock()
	return nil
}

// Helpers

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int8:
		return int(val)
	case int16:
		return int(val)
	case int32:
		return int(val)
	case int64:
		return int(val)
	case uint:
		return int(val)
	case uint8:
		return int(val)
	case uint16:
		return int(val)
	case uint32:
		return int(val)
	case uint64:
		return int(val)
	default:
		return 0
	}
}

func extractNameFromPath(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, "/", "\\"), "\\")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}

func getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
