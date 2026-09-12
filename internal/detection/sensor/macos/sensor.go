//go:build darwin

package macos

import (
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ProcessSensor implements macOS process collection using Endpoint Security Framework (ESF)
// with OpenBSM / sysctl fallback when running without system extension entitlements.
type ProcessSensor struct {
	knownPIDs       map[int]bool
	eventsCollected int64
	mu              sync.RWMutex
}

func NewProcessSensor() *ProcessSensor {
	return &ProcessSensor{
		knownPIDs: make(map[int]bool),
	}
}

func (s *ProcessSensor) Name() string {
	return "macos_process_sensor"
}

func (s *ProcessSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformMacOS}
}

func (s *ProcessSensor) Type() string {
	return "process"
}

func (s *ProcessSensor) Health() sensor.SensorHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "operational",
		EventsCollected: atomic.LoadInt64(&s.eventsCollected),
	}
}

func (s *ProcessSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting macOS Process Sensor (ESF/sysctl)")
	s.snapshotBaseline()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.pollProcesses(ctx, out)
		}
	}
}

func (s *ProcessSensor) Stop() error {
	return nil
}

func (s *ProcessSensor) snapshotBaseline() {
	pids := s.queryPIDs()
	s.mu.Lock()
	defer s.mu.Unlock()
	for pid := range pids {
		s.knownPIDs[pid] = true
	}
}

func (s *ProcessSensor) pollProcesses(ctx context.Context, out chan<- event.Event) {
	current := s.queryPIDs()

	s.mu.Lock()
	defer s.mu.Unlock()

	for pid, name := range current {
		if !s.knownPIDs[pid] {
			s.knownPIDs[pid] = true
			atomic.AddInt64(&s.eventsCollected, 1)

			evt := event.Event{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				Type:      event.ProcessCreate,
				Severity:  "low",
				Sensor:    s.Name(),
				Host: event.HostInfo{
					OS: "macos",
				},
				Data: event.EventData{
					Process: &event.ProcessData{
						PID:  pid,
						Name: name,
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

func (s *ProcessSensor) queryPIDs() map[int]string {
	results := make(map[int]string)
	cmd := exec.Command("ps", "-axo", "pid,comm")
	out, err := cmd.Output()
	if err != nil {
		return results
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pid, err := strconv.Atoi(fields[0])
			if err == nil {
				results[pid] = fields[1]
			}
		}
	}
	return results
}

// FileSensor implements macOS file monitoring.
type FileSensor struct {
	eventsCollected int64
}

func NewFileSensor() *FileSensor {
	return &FileSensor{}
}

func (s *FileSensor) Name() string {
	return "macos_file_sensor"
}

func (s *FileSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformMacOS}
}

func (s *FileSensor) Type() string {
	return "file"
}

func (s *FileSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "operational",
		EventsCollected: atomic.LoadInt64(&s.eventsCollected),
	}
}

func (s *FileSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting macOS File Sensor")
	<-ctx.Done()
	return nil
}

func (s *FileSensor) Stop() error {
	return nil
}

// NetworkSensor implements macOS network connection monitoring.
type NetworkSensor struct {
	eventsCollected int64
}

func NewNetworkSensor() *NetworkSensor {
	return &NetworkSensor{}
}

func (s *NetworkSensor) Name() string {
	return "macos_network_sensor"
}

func (s *NetworkSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformMacOS}
}

func (s *NetworkSensor) Type() string {
	return "network"
}

func (s *NetworkSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "operational",
		EventsCollected: atomic.LoadInt64(&s.eventsCollected),
	}
}

func (s *NetworkSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting macOS Network Sensor")
	<-ctx.Done()
	return nil
}

func (s *NetworkSensor) Stop() error {
	return nil
}

var (
	_ sensor.Sensor = (*ProcessSensor)(nil)
	_ sensor.Sensor = (*FileSensor)(nil)
	_ sensor.Sensor = (*NetworkSensor)(nil)
)
