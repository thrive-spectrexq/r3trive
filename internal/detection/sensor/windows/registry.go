//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const (
	RegistryProviderGUID = "{70eb4f03-c1de-4f73-a051-33d13d5413bd}"
	RegistrySensorName   = "WindowsRegistrySensor"
)

// RegistrySensor implements the sensor.Sensor interface for Windows Registry
// monitoring via ETW (Microsoft-Windows-Kernel-Registry provider).
type RegistrySensor struct {
	session  *etw.RealTimeSession
	consumer *etw.Consumer
	health   sensor.SensorHealth
	mu       sync.RWMutex
	cancel   context.CancelFunc
}

// NewRegistrySensor creates a new ETW-based registry sensor.
func NewRegistrySensor() *RegistrySensor {
	return &RegistrySensor{
		health: sensor.SensorHealth{
			Healthy: true,
			Status:  "Initialized",
		},
	}
}

// Name returns the sensor's unique identifier.
func (s *RegistrySensor) Name() string {
	return RegistrySensorName
}

// Platform returns the supported platforms.
func (s *RegistrySensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Health returns the current health status.
func (s *RegistrySensor) Health() sensor.SensorHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.health
}

// updateHealth updates the sensor's health status.
func (s *RegistrySensor) updateHealth(err error) {
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

// Start begins collecting ETW registry events.
func (s *RegistrySensor) Start(ctx context.Context, ch chan<- event.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	sessionName := fmt.Sprintf("R3TRIVE-Registry-%s", uuid.New().String()[:8])
	s.session = etw.NewRealTimeSession(sessionName)

	s.consumer = etw.NewRealTimeConsumer(ctx)
	s.consumer.FromSessions(s.session)

	s.consumer.EventCallback = func(e *etw.Event) error {
		// Skip QueryValue (ID 7) to reduce noise
		if e.System.EventID == 7 {
			return nil
		}

		var eventType event.EventType
		switch e.System.EventID {
		case 1: // CreateKey
			eventType = event.RegistryWrite
		case 2: // OpenKey
			eventType = event.RegistryRead
		case 3: // DeleteKey
			eventType = event.RegistryDelete
		case 5: // SetValue
			eventType = event.RegistryWrite
		case 6: // DeleteValue
			eventType = event.RegistryDelete
		default:
			return nil // Ignore other event types
		}

		// Extract registry properties
		keyName, _ := e.GetProperty("KeyName")
		if keyName == nil {
			keyName, _ = e.GetProperty("KeyObject")
		}
		valueName, _ := e.GetProperty("ValueName")
		valueType, _ := e.GetProperty("ValueType")
		valueData, _ := e.GetProperty("ValueData")
		if valueData == nil {
			valueData, _ = e.GetProperty("Value")
		}

		key := fmt.Sprintf("%v", keyName)
		vName := ""
		if valueName != nil {
			vName = fmt.Sprintf("%v", valueName)
		}
		vType := ""
		if valueType != nil {
			vType = fmt.Sprintf("%v", valueType)
		}
		vData := ""
		if valueData != nil {
			vData = fmt.Sprintf("%v", valueData)
		}

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
				Registry: &event.RegistryData{
					Key:       key,
					ValueName: vName,
					ValueType: vType,
					Value:     vData,
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

	provider, err := etw.ParseProvider(strings.Trim(RegistryProviderGUID, "{}"))
	if err != nil {
		s.updateHealth(err)
		return fmt.Errorf("failed to parse etw provider: %w", err)
	}
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

	slog.Info("started registry sensor", "session", sessionName)

	// Wait for context cancellation
	<-ctx.Done()
	return s.Stop()
}

// Stop stops the ETW session.
func (s *RegistrySensor) Stop() error {
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
