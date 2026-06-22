package windows

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const (
	KernelFileProviderGUID = "{edcb25e2-2aa7-400a-afad-5ea24c13a01a}"
	FileSensorName         = "WindowsFileSensor"
)

// FileSensor implements the sensor.Sensor interface using ETW.
type FileSensor struct {
	session  *etw.RealTimeSession
	consumer *etw.Consumer
	health   sensor.SensorHealth
	mu       sync.RWMutex
	cancel   context.CancelFunc
}

// NewFileSensor creates a new ETW-based file sensor.
func NewFileSensor() *FileSensor {
	return &FileSensor{
		health: sensor.SensorHealth{
			Healthy: true,
			Status:  "Initialized",
		},
	}
}

// Name returns the sensor's unique identifier.
func (s *FileSensor) Name() string {
	return FileSensorName
}

// Platform returns the supported platforms.
func (s *FileSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Health returns the current health status.
func (s *FileSensor) Health() sensor.SensorHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.health
}

// updateHealth updates the sensor's health status.
func (s *FileSensor) updateHealth(err error) {
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

// Start begins collecting ETW file events.
func (s *FileSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	sessionName := fmt.Sprintf("R3TRIVE-File-%s", uuid.New().String()[:8])
	s.session = etw.NewRealTimeSession(sessionName)

	s.consumer = etw.NewRealTimeConsumer(ctx)
	s.consumer.FromSessions(s.session)

	s.consumer.EventCallback = func(e *etw.Event) error {
		// Example Event IDs for File (varies, but roughly):
		// 10, 11 -> Create, 13 -> Delete, 14 -> Rename
		// For simplicity, we capture create/delete/rename if we can identify them.
		var eventType event.EventType
		switch e.System.EventID {
		case 10, 11, 12, 30:
			eventType = event.FileCreate
		case 13, 26, 27:
			eventType = event.FileDelete
		case 14:
			eventType = event.FileRename
		default:
			// Treat other writes as modify
			eventType = event.FileModify
		}

		pid, _ := e.GetProperty("ProcessID")
		if pid == nil {
			pid, _ = e.GetProperty("PID")
		}

		fileName, _ := e.GetProperty("FileName")
		if fileName == nil {
			// Skip if no file name
			return nil
		}

		path := fmt.Sprintf("%v", fileName)
		name := extractNameFromPath(path)

		ev := event.Event{
			ID:        fmt.Sprintf("evt_%s", uuid.New().String()),
			Timestamp: e.System.TimeCreated.SystemTime.UTC(),
			Host: event.HostInfo{
				Hostname: getHostname(),
				OS:       "windows",
			},
			Type:     eventType,
			Severity: event.SeverityLow,
			Sensor:   s.Name(),
			Data: event.EventData{
				File: &event.FileData{
					Path: path,
					Name: name,
				},
			},
		}

		// Also attach pid to raw data or enrichments since file events don't strictly have a PID in FileData in our schema
		ev.Data.Raw = map[string]any{
			"process_pid": toInt(pid),
		}

		select {
		case ch <- ev:
			s.updateHealth(nil)
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}

	provider := etw.MustParseProvider(KernelFileProviderGUID)
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
func (s *FileSensor) Stop() error {
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
