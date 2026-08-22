//go:build linux

package linux

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type NetworkSensor struct {
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	eventsCollected atomic.Int64
	errorCount      atomic.Int64
	lastEventTime   atomic.Pointer[time.Time]
	healthy         atomic.Bool
	status          atomic.Pointer[string]

	knownConnections map[string]bool
	mu               sync.RWMutex
}

func NewNetworkSensor() sensor.Sensor {
	s := &NetworkSensor{
		knownConnections: make(map[string]bool),
	}
	s.setStatus("Initialized")
	s.healthy.Store(true)
	return s
}

func (s *NetworkSensor) Name() string {
	return "linux_network"
}

func (s *NetworkSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformLinux}
}

func (s *NetworkSensor) setStatus(status string) {
	s.status.Store(&status)
}

func (s *NetworkSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	s.setStatus("Running")
	s.healthy.Store(true)

	s.wg.Add(1)
	go s.monitor(ctx, ch)

	return nil
}

func (s *NetworkSensor) monitor(ctx context.Context, ch chan<- event.Event) {
	defer s.wg.Done()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	hostname, _ := os.Hostname()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pollConnections(ctx, ch, "/proc/net/tcp", "tcp", hostname)
			s.pollConnections(ctx, ch, "/proc/net/udp", "udp", hostname)
		}
	}
}

func (s *NetworkSensor) pollConnections(ctx context.Context, ch chan<- event.Event, path string, protocol string, hostname string) {
	//#nosec G304
	file, err := os.Open(path)
	if err != nil {
		s.errorCount.Add(1)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true

	currentConns := make(map[string]bool)

	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}

		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		srcIP, srcPort, err := parseHexIPPort(fields[1])
		if err != nil {
			continue
		}

		dstIP, dstPort, err := parseHexIPPort(fields[2])
		if err != nil {
			continue
		}

		connID := fmt.Sprintf("%s-%s:%d-%s:%d", protocol, srcIP, srcPort, dstIP, dstPort)
		currentConns[connID] = true

		s.mu.RLock()
		isKnown := s.knownConnections[connID]
		s.mu.RUnlock()

		if !isKnown {
			e := event.Event{
				ID:        fmt.Sprintf("net_%d", time.Now().UnixNano()),
				Type:      event.NetworkConnect,
				Timestamp: time.Now().UTC(),
				Severity:  event.SeverityLow,
				Sensor:    s.Name(),
				Host: event.HostInfo{
					Hostname: hostname,
					OS:       "linux",
				},
				Data: event.EventData{
					Network: &event.NetworkData{
						SrcIP:    srcIP,
						SrcPort:  int(srcPort),
						DstIP:    dstIP,
						DstPort:  int(dstPort),
						Protocol: protocol,
					},
				},
			}

			select {
			case ch <- e:
				s.eventsCollected.Add(1)
				now := time.Now()
				s.lastEventTime.Store(&now)
			case <-ctx.Done():
				return
			default:
				s.errorCount.Add(1)
			}
		}
	}

	s.mu.Lock()
	for k := range s.knownConnections {
		if strings.HasPrefix(k, protocol+"-") && !currentConns[k] {
			delete(s.knownConnections, k)
		}
	}
	for k := range currentConns {
		s.knownConnections[k] = true
	}
	s.mu.Unlock()
}

func parseHexIPPort(hexStr string) (string, uint16, error) {
	parts := strings.Split(hexStr, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid format")
	}

	ipHex := parts[0]
	portHex := parts[1]

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil || len(ipBytes) != 4 {
		return "", 0, fmt.Errorf("invalid IP hex")
	}
	// Little endian for IPv4 in /proc/net/tcp
	ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()

	portInt, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port hex")
	}

	return ip, uint16(portInt), nil
}

func (s *NetworkSensor) Stop() error {
	if s.cancel != nil {
		s.cancel()
		s.wg.Wait()
	}
	s.setStatus("Stopped")
	s.healthy.Store(false)
	return nil
}

func (s *NetworkSensor) Health() sensor.SensorHealth {
	var lastTimeStr string
	if lt := s.lastEventTime.Load(); lt != nil {
		lastTimeStr = lt.Format(time.RFC3339)
	}

	status := "Unknown"
	if st := s.status.Load(); st != nil {
		status = *st
	}

	return sensor.SensorHealth{
		Healthy:         s.healthy.Load(),
		Status:          status,
		EventsCollected: s.eventsCollected.Load(),
		LastEventTime:   lastTimeStr,
		ErrorCount:      s.errorCount.Load(),
	}
}
