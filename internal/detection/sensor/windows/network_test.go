//go:build windows

package windows

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestWindowsNetworkSensor_Metadata(t *testing.T) {
	s := NewNetworkSensor()

	if s.Name() != "windows_network_sensor" {
		t.Errorf("expected name windows_network_sensor, got %s", s.Name())
	}

	if s.Type() != "network" {
		t.Errorf("expected type network, got %s", s.Type())
	}

	platforms := s.Platform()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Errorf("unexpected platforms: %v", platforms)
	}

	h := s.Health()
	if !h.Healthy {
		t.Errorf("expected initial health to be healthy")
	}

	if err := s.Stop(); err != nil {
		t.Errorf("expected Stop to return nil, got %v", err)
	}

	h = s.Health()
	if h.Status != "stopped" {
		t.Errorf("expected status stopped, got %s", h.Status)
	}
}

func TestWindowsNetworkSensor_ParseHelpers(t *testing.T) {
	// Test IPv4 parsing
	// 127.0.0.1 in network byte order in 32-bit int: byte0=127, byte1=0, byte2=0, byte3=1
	// dwAddr = 127 | (0 << 8) | (0 << 16) | (1 << 24) = 0x0100007F
	loopbackDw := uint32(127) | (uint32(1) << 24)
	ipStr := parseIPv4(loopbackDw)
	if ipStr != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", ipStr)
	}

	// Test port parsing
	// Port 80 (0x0050): stored as 0x5000 in uint16 on little-endian
	port80Dw := uint32(0x5000)
	port := parsePort(port80Dw)
	if port != 80 {
		t.Errorf("expected port 80, got %d", port)
	}

	// Port 443 (0x01BB): stored as 0xBB01 in uint16
	port443Dw := uint32(0xBB01)
	port = parsePort(port443Dw)
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}

	// Test buildConnectionKey
	recListen := connRecord{
		protocol: "tcp",
		srcIP:    "127.0.0.1",
		srcPort:  8080,
		dstIP:    "0.0.0.0",
		dstPort:  0,
		pid:      1234,
		state:    tcpStateListen,
	}
	keyListen := buildConnectionKey(recListen)
	if keyListen != "tcp:listen:127.0.0.1:8080:1234" {
		t.Errorf("unexpected listen key: %s", keyListen)
	}

	recUdp6 := connRecord{
		protocol: "udp6",
		srcIP:    "::",
		srcPort:  5353,
		dstIP:    "::",
		dstPort:  0,
		pid:      5678,
		state:    tcpStateListen,
	}
	keyUdp6 := buildConnectionKey(recUdp6)
	if keyUdp6 != "udp6:listen::::5353:5678" {
		t.Errorf("unexpected udp6 key: %s", keyUdp6)
	}

	recConn := connRecord{
		protocol: "tcp",
		srcIP:    "127.0.0.1",
		srcPort:  50000,
		dstIP:    "127.0.0.1",
		dstPort:  8080,
		pid:      1234,
		state:    tcpStateEstab,
	}
	keyConn := buildConnectionKey(recConn)
	if keyConn != "tcp:conn:127.0.0.1:50000->127.0.0.1:8080:1234" {
		t.Errorf("unexpected conn key: %s", keyConn)
	}
}

func TestWindowsNetworkSensor_TableQueries(t *testing.T) {
	procMap := getProcessMap()
	if len(procMap) == 0 {
		t.Fatalf("expected non-empty process map")
	}

	// Check current PID is in process map
	currentPID := uint32(os.Getpid())
	if _, ok := procMap[currentPID]; !ok {
		t.Logf("current PID %d not directly resolved in snapshot", currentPID)
	}

	// Query IPv4 TCP table
	tcpBuf, err := getExtendedTcpTable(afINET)
	if err != nil {
		t.Fatalf("getExtendedTcpTable failed: %v", err)
	}
	records := parseTcpTableIPv4(tcpBuf, procMap)
	if len(records) == 0 {
		t.Log("no active IPv4 TCP connections found")
	} else {
		sample := records[0]
		t.Logf("sample TCP connection: %s %s:%d -> %s:%d (pid: %d, proc: %s)",
			sample.protocol, sample.srcIP, sample.srcPort, sample.dstIP, sample.dstPort, sample.pid, sample.procName)
	}

	// Query IPv4 UDP table
	udpBuf, err := getExtendedUdpTable(afINET)
	if err != nil {
		t.Fatalf("getExtendedUdpTable failed: %v", err)
	}
	udpRecords := parseUdpTableIPv4(udpBuf, procMap)
	if len(udpRecords) == 0 {
		t.Log("no active IPv4 UDP endpoints found")
	} else {
		sample := udpRecords[0]
		t.Logf("sample UDP endpoint: %s %s:%d (pid: %d, proc: %s)",
			sample.protocol, sample.srcIP, sample.srcPort, sample.pid, sample.procName)
	}
}

func TestWindowsNetworkSensor_LifecycleAndDetection(t *testing.T) {
	s := NewNetworkSensorWithInterval(50 * time.Millisecond)

	ch := make(chan event.Event, 200)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx, ch)
	}()

	// Allow baseline snapshot to populate
	time.Sleep(150 * time.Millisecond)

	// Create a new TCP listener to trigger detection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	expectedPort, _ := strconv.Atoi(portStr)

	// Connect to the listener
	conn, err := net.Dial("tcp", addr)
	if err == nil {
		defer conn.Close()
	}

	// Collect events until we see our listener or timeout
	foundListener := false
	timeout := time.After(4 * time.Second)

	for !foundListener {
		select {
		case ev := <-ch:
			if ev.Data.Network != nil {
				if ev.Type == event.NetworkListen && ev.Data.Network.SrcPort == expectedPort {
					t.Logf("detected network event: %s %s:%d -> %s:%d (pid: %d, proc: %s)",
						ev.Type,
						ev.Data.Network.SrcIP, ev.Data.Network.SrcPort,
						ev.Data.Network.DstIP, ev.Data.Network.DstPort,
						ev.Data.Network.ProcessPID, ev.Data.Network.ProcessName)

					if ev.Data.Network.ProcessPID != os.Getpid() {
						t.Errorf("expected PID %d, got %d", os.Getpid(), ev.Data.Network.ProcessPID)
					}
					foundListener = true
				}
			}
		case <-timeout:
			t.Fatalf("timed out waiting for network event on expected port %d", expectedPort)
		}
	}

	_ = s.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sensor Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sensor did not stop in time")
	}

	h := s.Health()
	if !h.Healthy {
		t.Errorf("expected sensor to be healthy")
	}
}
