//go:build windows

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
	KernelNetworkProviderGUID = "{7dd42a49-5329-4832-8dfd-43d979153a88}"
	NetworkSensorName         = "WindowsNetworkSensor"
)

// NetworkSensor implements the sensor.Sensor interface using ETW.
type NetworkSensor struct {
	session  *etw.RealTimeSession
	consumer *etw.Consumer
	health   sensor.SensorHealth
	mu       sync.RWMutex
	cancel   context.CancelFunc
}

// NewNetworkSensor creates a new ETW-based network sensor.
func NewNetworkSensor() *NetworkSensor {
	return &NetworkSensor{
		health: sensor.SensorHealth{
			Healthy: true,
			Status:  "Initialized",
		},
	}
}

// Name returns the sensor's unique identifier.
func (s *NetworkSensor) Name() string {
	return NetworkSensorName
}

// Platform returns the supported platforms.
func (s *NetworkSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Health returns the current health status.
func (s *NetworkSensor) Health() sensor.SensorHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.health
}

// updateHealth updates the sensor's health status.
func (s *NetworkSensor) updateHealth(err error) {
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

// Start begins collecting ETW network events.
func (s *NetworkSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	sessionName := fmt.Sprintf("R3TRIVE-Network-%s", uuid.New().String()[:8])
	s.session = etw.NewRealTimeSession(sessionName)

	s.consumer = etw.NewRealTimeConsumer(ctx)
	s.consumer.FromSessions(s.session)

	s.consumer.EventCallback = func(e *etw.Event) error {
		// Event ID 10: TCP Connect, 11: TCP Accept, etc.
		// For simplicity, we capture anything that has connection semantics
		var eventType event.EventType
		switch e.System.EventID {
		case 10, 12, 14:
			eventType = event.NetworkConnect
		case 11, 13, 15:
			eventType = event.NetworkListen
		default:
			// Treat other events (like send/recv) as send if we care, or just connect for now
			eventType = event.NetworkConnect
		}

		pid, _ := e.GetProperty("PID")
		if pid == nil {
			pid, _ = e.GetProperty("ProcessID")
		}
		
		daddr, _ := e.GetProperty("daddr")
		saddr, _ := e.GetProperty("saddr")
		dport, _ := e.GetProperty("dport")
		sport, _ := e.GetProperty("sport")
		protocol, _ := e.GetProperty("protocol") // Could be IPPROTO

		// Only emit if we have some IP data
		if daddr == nil && saddr == nil {
			return nil
		}

		ev := event.Event{
			ID:        fmt.Sprintf("evt_%s", uuid.New().String()),
			Timestamp: e.System.TimeCreated.SystemTime.UTC(),
			Host: event.HostInfo{
				Hostname: getHostname(), // From process.go or we redefine
				OS:       "windows",
			},
			Type:     eventType,
			Severity: event.SeverityLow,
			Sensor:   s.Name(),
			Data: event.EventData{
				Network: &event.NetworkData{
					Protocol:   fmt.Sprintf("%v", protocol),
					SrcIP:      fmt.Sprintf("%v", saddr),
					SrcPort:    toInt(sport),
					DstIP:      fmt.Sprintf("%v", daddr),
					DstPort:    toInt(dport),
					ProcessPID: toInt(pid),
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

	provider := etw.MustParseProvider(KernelNetworkProviderGUID)
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
func (s *NetworkSensor) Stop() error {
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


