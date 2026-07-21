//go:build linux

package linux

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// ProcessSensor implements the Linux process monitoring sensor via /proc polling.
type ProcessSensor struct {
	knownPIDs       map[int]bool
	eventsCollected int64
}

// NewProcessSensor creates a new Linux process sensor.
func NewProcessSensor() *ProcessSensor {
	return &ProcessSensor{
		knownPIDs: make(map[int]bool),
	}
}

func (s *ProcessSensor) Name() string {
	return "linux_process_sensor"
}

func (s *ProcessSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformLinux}
}

func (s *ProcessSensor) Type() string {
	return "process"
}

func (s *ProcessSensor) Health() sensor.SensorHealth {
	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "operational",
		EventsCollected: s.eventsCollected,
	}
}

func (s *ProcessSensor) Start(ctx context.Context, out chan<- event.Event) error {
	slog.Info("starting Linux process sensor (/proc polling)")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.pollProcFS(ctx, out)
		}
	}
}

func (s *ProcessSensor) pollProcFS(ctx context.Context, out chan<- event.Event) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	currentPIDs := make(map[int]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		currentPIDs[pid] = true

		if !s.knownPIDs[pid] {
			// New process detected
			s.knownPIDs[pid] = true
			s.eventsCollected++

			cmdlineBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

			evt := event.Event{
				ID:        fmt.Sprintf("proc_%d_%d", pid, time.Now().UnixNano()),
				Timestamp: time.Now().UTC(),
				Type:      event.ProcessCreate,
				Severity:  event.SeverityLow,
				Sensor:    s.Name(),
				Data: event.EventData{
					Process: &event.ProcessData{
						PID:     pid,
						Name:    entry.Name(),
						CmdLine: strings.TrimSpace(cmdline),
						Path:    fmt.Sprintf("/proc/%d/exe", pid),
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

	// Clean up exited PIDs
	for pid := range s.knownPIDs {
		if !currentPIDs[pid] {
			delete(s.knownPIDs, pid)
		}
	}
}

func (s *ProcessSensor) Stop() error {
	return nil
}

var _ sensor.Sensor = (*ProcessSensor)(nil)
