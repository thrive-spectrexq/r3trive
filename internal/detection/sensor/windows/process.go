//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ProcessSensor implements a native Windows process monitoring sensor via Toolhelp32 snapshots.
type ProcessSensor struct {
	mu              sync.RWMutex
	knownPIDs       map[uint32]string
	pollInterval    time.Duration
	eventsCollected atomic.Int64
	errorCount      atomic.Int64
	lastEventTime   time.Time
}

// NewProcessSensor creates a new Windows process sensor with default 1-second polling.
func NewProcessSensor() *ProcessSensor {
	return NewProcessSensorWithInterval(1 * time.Second)
}

// NewProcessSensorWithInterval creates a Windows process sensor with a configurable polling interval.
func NewProcessSensorWithInterval(interval time.Duration) *ProcessSensor {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	return &ProcessSensor{
		knownPIDs:    make(map[uint32]string),
		pollInterval: interval,
	}
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
	s.mu.RLock()
	lastTime := s.lastEventTime
	s.mu.RUnlock()

	lastTimeStr := ""
	if !lastTime.IsZero() {
		lastTimeStr = lastTime.UTC().Format(time.RFC3339)
	}

	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "operational",
		EventsCollected: s.eventsCollected.Load(),
		LastEventTime:   lastTimeStr,
		ErrorCount:      s.errorCount.Load(),
	}
}

// Start polls the Windows process list and emits ProcessCreate events.
func (s *ProcessSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting Windows native process sensor (Toolhelp32)")

	// Initial baseline snapshot to populate known PIDs without emitting flood of events
	s.populateInitialSnapshot()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("stopping Windows native process sensor")
			return nil
		case <-ticker.C:
			s.pollProcesses(ctx, out)
		}
	}
}

// populateInitialSnapshot records current processes to avoid generating false creation events for pre-existing processes.
func (s *ProcessSensor) populateInitialSnapshot() {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		s.errorCount.Add(1)
		slog.Error("failed to create initial toolhelp snapshot", "error", err)
		return
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := syscall.Process32First(handle, &entry); err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		exeName := syscall.UTF16ToString(entry.ExeFile[:])
		s.knownPIDs[entry.ProcessID] = exeName
		if err := syscall.Process32Next(handle, &entry); err != nil {
			break
		}
	}
}

// pollProcesses takes a snapshot and checks for newly created processes.
func (s *ProcessSensor) pollProcesses(ctx context.Context, out chan<- event.Event) {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		s.errorCount.Add(1)
		slog.Error("failed to create toolhelp snapshot", "error", err)
		return
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := syscall.Process32First(handle, &entry); err != nil {
		return
	}

	currentPIDs := make(map[uint32]bool)
	var newProcesses []syscall.ProcessEntry32

	s.mu.Lock()
	for {
		pid := entry.ProcessID
		currentPIDs[pid] = true
		exeName := syscall.UTF16ToString(entry.ExeFile[:])

		if _, exists := s.knownPIDs[pid]; !exists {
			s.knownPIDs[pid] = exeName
			newProcesses = append(newProcesses, entry)
		}

		if err := syscall.Process32Next(handle, &entry); err != nil {
			break
		}
	}

	// Evict terminated processes
	for pid := range s.knownPIDs {
		if !currentPIDs[pid] {
			delete(s.knownPIDs, pid)
		}
	}
	s.mu.Unlock()

	// Emit events for new processes
	for _, proc := range newProcesses {
		exeName := syscall.UTF16ToString(proc.ExeFile[:])
		now := time.Now().UTC()

		s.mu.Lock()
		parentName := s.knownPIDs[proc.ParentProcessID]
		s.lastEventTime = now
		s.mu.Unlock()

		s.eventsCollected.Add(1)

		evt := event.Event{
			ID:        fmt.Sprintf("winproc_%d_%d", proc.ProcessID, now.UnixNano()),
			Timestamp: now,
			Type:      event.ProcessCreate,
			Severity:  event.SeverityLow,
			Sensor:    s.Name(),
			Data: event.EventData{
				Process: &event.ProcessData{
					PID:     int(proc.ProcessID),
					PPID:    int(proc.ParentProcessID),
					Name:    exeName,
					Path:    exeName,
					CmdLine: exeName,
					Parent: &event.ParentProcess{
						PID:  int(proc.ParentProcessID),
						Name: parentName,
					},
				},
			},
		}

		select {
		case <-ctx.Done():
			return
		case out <- evt:
		}
	}
}

// Stop halts the sensor.
func (s *ProcessSensor) Stop() error {
	return nil
}

var _ sensor.Sensor = (*ProcessSensor)(nil)
