//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const (
	NetworkSensorName = "windows_network_sensor"

	afINET  = 2
	afINET6 = 23

	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1

	tcpStateClosed    = 1
	tcpStateListen    = 2
	tcpStateSynSent   = 3
	tcpStateSynRcvd   = 4
	tcpStateEstab     = 5
	tcpStateFinWait1  = 6
	tcpStateFinWait2  = 7
	tcpStateCloseWait = 8
	tcpStateClosing   = 9
	tcpStateLastAck   = 10
	tcpStateTimeWait  = 11
	tcpStateDeleteTCB = 12
)

var (
	modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

type mibTcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type mibUdpRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type mibTcp6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

type mibUdp6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeId uint32
	LocalPort    uint32
	OwningPid    uint32
}

type connRecord struct {
	protocol string
	srcIP    string
	srcPort  int
	dstIP    string
	dstPort  int
	pid      int
	procName string
	state    uint32
}

// NetworkSensor implements a native Windows network sensor using iphlpapi.dll.
// It tracks active TCP/UDP connections and listeners without requiring Administrator privileges.
type NetworkSensor struct {
	mu               sync.RWMutex
	knownConnections map[string]bool
	pollInterval     time.Duration
	eventsCollected  atomic.Int64
	errorCount       atomic.Int64
	lastEventTime    time.Time
	cancel           context.CancelFunc
	running          atomic.Bool
}

// NewNetworkSensor creates a new native Windows network sensor with a 1-second polling interval.
func NewNetworkSensor() *NetworkSensor {
	return NewNetworkSensorWithInterval(1 * time.Second)
}

// NewNetworkSensorWithInterval creates a native Windows network sensor with a custom polling interval.
func NewNetworkSensorWithInterval(interval time.Duration) *NetworkSensor {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	return &NetworkSensor{
		knownConnections: make(map[string]bool),
		pollInterval:     interval,
	}
}

// Name returns the sensor identifier.
func (s *NetworkSensor) Name() string {
	return NetworkSensorName
}

// Platform returns the supported platform.
func (s *NetworkSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Type returns the event category.
func (s *NetworkSensor) Type() string {
	return "network"
}

// Health returns current sensor diagnostics.
func (s *NetworkSensor) Health() sensor.SensorHealth {
	s.mu.RLock()
	lastTime := s.lastEventTime
	s.mu.RUnlock()

	lastTimeStr := ""
	if !lastTime.IsZero() {
		lastTimeStr = lastTime.UTC().Format(time.RFC3339)
	}

	status := "operational"
	if !s.running.Load() {
		status = "stopped"
	}

	return sensor.SensorHealth{
		Healthy:         true,
		Status:          status,
		EventsCollected: s.eventsCollected.Load(),
		LastEventTime:   lastTimeStr,
		ErrorCount:      s.errorCount.Load(),
	}
}

// Start begins polling native Windows TCP/UDP connection tables and emits network events.
func (s *NetworkSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	slog.Info("starting Windows native network sensor (iphlpapi)")

	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	s.running.Store(true)

	// Populate baseline connections to avoid flooding events on startup
	s.populateInitialSnapshot()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("stopping Windows native network sensor")
			_ = s.Stop()
			return nil
		case <-ticker.C:
			s.pollNetwork(ctx, ch)
		}
	}
}

// Stop terminates network monitoring and updates health status.
func (s *NetworkSensor) Stop() error {
	s.running.Store(false)
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

// populateInitialSnapshot captures active connections at startup so only new connections trigger events.
func (s *NetworkSensor) populateInitialSnapshot() {
	records, err := s.collectCurrentConnections()
	if err != nil {
		s.errorCount.Add(1)
		slog.Error("failed to take initial network snapshot", "error", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rec := range records {
		key := buildConnectionKey(rec)
		s.knownConnections[key] = true
	}
}

// pollNetwork checks current connections against known connections and emits new events.
func (s *NetworkSensor) pollNetwork(ctx context.Context, ch chan<- event.Event) {
	records, err := s.collectCurrentConnections()
	if err != nil {
		s.errorCount.Add(1)
		slog.Error("failed to collect network connections", "error", err)
		return
	}

	currentKeys := make(map[string]bool, len(records))
	var newRecords []connRecord

	s.mu.Lock()
	for _, rec := range records {
		key := buildConnectionKey(rec)
		currentKeys[key] = true

		if !s.knownConnections[key] {
			s.knownConnections[key] = true
			newRecords = append(newRecords, rec)
		}
	}

	// Evict connections that are no longer present
	for key := range s.knownConnections {
		if !currentKeys[key] {
			delete(s.knownConnections, key)
		}
	}
	s.mu.Unlock()

	// Emit events for new connections
	hostname := getHostname()
	for _, rec := range newRecords {
		eventType := event.NetworkConnect
		if rec.state == tcpStateListen || rec.protocol == "udp" || rec.protocol == "udp6" || (rec.dstIP == "0.0.0.0" && rec.dstPort == 0) || (rec.dstIP == "::" && rec.dstPort == 0) {
			eventType = event.NetworkListen
		}

		now := time.Now().UTC()
		ev := event.Event{
			ID:        fmt.Sprintf("winnet_%s", uuid.New().String()),
			Timestamp: now,
			Host: event.HostInfo{
				Hostname: hostname,
				OS:       "windows",
			},
			Type:     eventType,
			Severity: event.SeverityLow,
			Sensor:   s.Name(),
			Data: event.EventData{
				Network: &event.NetworkData{
					Protocol:    rec.protocol,
					SrcIP:       rec.srcIP,
					SrcPort:     rec.srcPort,
					DstIP:       rec.dstIP,
					DstPort:     rec.dstPort,
					ProcessPID:  rec.pid,
					ProcessName: rec.procName,
				},
			},
		}

		select {
		case ch <- ev:
			s.eventsCollected.Add(1)
			s.mu.Lock()
			s.lastEventTime = now
			s.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

// collectCurrentConnections retrieves TCP and UDP connection tables for IPv4 and IPv6.
func (s *NetworkSensor) collectCurrentConnections() ([]connRecord, error) {
	procMap := getProcessMap()
	var allRecords []connRecord

	// TCP IPv4
	tcp4Buf, err := getExtendedTcpTable(afINET)
	if err == nil {
		allRecords = append(allRecords, parseTcpTableIPv4(tcp4Buf, procMap)...)
	} else {
		slog.Debug("failed to query TCP IPv4 table", "error", err)
	}

	// TCP IPv6
	tcp6Buf, err := getExtendedTcpTable(afINET6)
	if err == nil {
		allRecords = append(allRecords, parseTcpTableIPv6(tcp6Buf, procMap)...)
	} else {
		slog.Debug("failed to query TCP IPv6 table", "error", err)
	}

	// UDP IPv4
	udp4Buf, err := getExtendedUdpTable(afINET)
	if err == nil {
		allRecords = append(allRecords, parseUdpTableIPv4(udp4Buf, procMap)...)
	} else {
		slog.Debug("failed to query UDP IPv4 table", "error", err)
	}

	// UDP IPv6
	udp6Buf, err := getExtendedUdpTable(afINET6)
	if err == nil {
		allRecords = append(allRecords, parseUdpTableIPv6(udp6Buf, procMap)...)
	} else {
		slog.Debug("failed to query UDP IPv6 table", "error", err)
	}

	return allRecords, nil
}

func getExtendedTcpTable(family uint32) ([]byte, error) {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if ret != 0 && ret != 122 { // 122 = ERROR_INSUFFICIENT_BUFFER
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed: errno %d", ret)
	}
	if size == 0 {
		return nil, nil
	}

	for attempts := 0; attempts < 3; attempts++ {
		buf := make([]byte, size)
		ret, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(family),
			uintptr(tcpTableOwnerPIDAll),
			0,
		)
		if ret == 0 {
			return buf, nil
		}
		if ret == 122 {
			if size == 0 {
				return nil, nil
			}
			continue
		}
		return nil, fmt.Errorf("GetExtendedTcpTable failed: errno %d", ret)
	}
	return nil, fmt.Errorf("GetExtendedTcpTable failed after buffer retries")
}

func getExtendedUdpTable(family uint32) ([]byte, error) {
	var size uint32
	ret, _, _ := procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(udpTableOwnerPID),
		0,
	)
	if ret != 0 && ret != 122 {
		return nil, fmt.Errorf("GetExtendedUdpTable size query failed: errno %d", ret)
	}
	if size == 0 {
		return nil, nil
	}

	for attempts := 0; attempts < 3; attempts++ {
		buf := make([]byte, size)
		ret, _, _ = procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(family),
			uintptr(udpTableOwnerPID),
			0,
		)
		if ret == 0 {
			return buf, nil
		}
		if ret == 122 {
			if size == 0 {
				return nil, nil
			}
			continue
		}
		return nil, fmt.Errorf("GetExtendedUdpTable failed: errno %d", ret)
	}
	return nil, fmt.Errorf("GetExtendedUdpTable failed after buffer retries")
}

func parseTcpTableIPv4(buf []byte, procMap map[uint32]string) []connRecord {
	if len(buf) < 4 {
		return nil
	}
	numEntries := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(mibTcpRowOwnerPID{}))
	if len(buf) < 4+numEntries*rowSize {
		return nil
	}

	records := make([]connRecord, 0, numEntries)
	for i := 0; i < numEntries; i++ {
		offset := 4 + i*rowSize
		row := (*mibTcpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		records = append(records, connRecord{
			protocol: "tcp",
			srcIP:    parseIPv4(row.LocalAddr),
			srcPort:  parsePort(row.LocalPort),
			dstIP:    parseIPv4(row.RemoteAddr),
			dstPort:  parsePort(row.RemotePort),
			pid:      int(row.OwningPid),
			procName: procMap[row.OwningPid],
			state:    row.State,
		})
	}
	return records
}

func parseTcpTableIPv6(buf []byte, procMap map[uint32]string) []connRecord {
	if len(buf) < 4 {
		return nil
	}
	numEntries := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(mibTcp6RowOwnerPID{}))
	if len(buf) < 4+numEntries*rowSize {
		return nil
	}

	records := make([]connRecord, 0, numEntries)
	for i := 0; i < numEntries; i++ {
		offset := 4 + i*rowSize
		row := (*mibTcp6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		records = append(records, connRecord{
			protocol: "tcp6",
			srcIP:    net.IP(row.LocalAddr[:]).String(),
			srcPort:  parsePort(row.LocalPort),
			dstIP:    net.IP(row.RemoteAddr[:]).String(),
			dstPort:  parsePort(row.RemotePort),
			pid:      int(row.OwningPid),
			procName: procMap[row.OwningPid],
			state:    row.State,
		})
	}
	return records
}

func parseUdpTableIPv4(buf []byte, procMap map[uint32]string) []connRecord {
	if len(buf) < 4 {
		return nil
	}
	numEntries := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(mibUdpRowOwnerPID{}))
	if len(buf) < 4+numEntries*rowSize {
		return nil
	}

	records := make([]connRecord, 0, numEntries)
	for i := 0; i < numEntries; i++ {
		offset := 4 + i*rowSize
		row := (*mibUdpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		records = append(records, connRecord{
			protocol: "udp",
			srcIP:    parseIPv4(row.LocalAddr),
			srcPort:  parsePort(row.LocalPort),
			dstIP:    "0.0.0.0",
			dstPort:  0,
			pid:      int(row.OwningPid),
			procName: procMap[row.OwningPid],
			state:    tcpStateListen,
		})
	}
	return records
}

func parseUdpTableIPv6(buf []byte, procMap map[uint32]string) []connRecord {
	if len(buf) < 4 {
		return nil
	}
	numEntries := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(mibUdp6RowOwnerPID{}))
	if len(buf) < 4+numEntries*rowSize {
		return nil
	}

	records := make([]connRecord, 0, numEntries)
	for i := 0; i < numEntries; i++ {
		offset := 4 + i*rowSize
		row := (*mibUdp6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		records = append(records, connRecord{
			protocol: "udp6",
			srcIP:    net.IP(row.LocalAddr[:]).String(),
			srcPort:  parsePort(row.LocalPort),
			dstIP:    "::",
			dstPort:  0,
			pid:      int(row.OwningPid),
			procName: procMap[row.OwningPid],
			state:    tcpStateListen,
		})
	}
	return records
}

func parseIPv4(dwAddr uint32) string {
	return net.IPv4(
		byte(dwAddr),
		byte(dwAddr>>8),
		byte(dwAddr>>16),
		byte(dwAddr>>24),
	).String()
}

func parsePort(dwPort uint32) int {
	p := uint16(dwPort)
	return int((p >> 8) | (p << 8))
}

func buildConnectionKey(rec connRecord) string {
	if rec.state == tcpStateListen || rec.protocol == "udp" || rec.protocol == "udp6" || (rec.dstIP == "0.0.0.0" && rec.dstPort == 0) || (rec.dstIP == "::" && rec.dstPort == 0) {
		return fmt.Sprintf("%s:listen:%s:%d:%d", rec.protocol, rec.srcIP, rec.srcPort, rec.pid)
	}
	return fmt.Sprintf("%s:conn:%s:%d->%s:%d:%d", rec.protocol, rec.srcIP, rec.srcPort, rec.dstIP, rec.dstPort, rec.pid)
}

func getProcessMap() map[uint32]string {
	res := make(map[uint32]string)
	res[0] = "System Idle Process"
	res[4] = "System"

	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return res
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := syscall.Process32First(handle, &entry); err != nil {
		return res
	}

	for {
		res[entry.ProcessID] = syscall.UTF16ToString(entry.ExeFile[:])
		if err := syscall.Process32Next(handle, &entry); err != nil {
			break
		}
	}
	return res
}

var _ sensor.Sensor = (*NetworkSensor)(nil)
