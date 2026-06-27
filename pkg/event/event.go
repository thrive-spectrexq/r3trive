// Package event defines the core event types used throughout R3TRIVE.
// All sensors produce events conforming to this schema, and all subsystems
// consume them through these types.
package event

import (
	"encoding/json"
	"fmt"
	"time"
)

// EventType represents the category of an observable event.
type EventType string

// Event type constants for all supported event categories.
const (
	// Process events
	ProcessCreate EventType = "process.create"
	ProcessExit   EventType = "process.exit"
	ProcessInject EventType = "process.inject"

	// File events
	FileCreate EventType = "file.create"
	FileModify EventType = "file.modify"
	FileDelete EventType = "file.delete"
	FileRename EventType = "file.rename"

	// Network events
	NetworkConnect EventType = "network.connect"
	NetworkListen  EventType = "network.listen"
	NetworkSend    EventType = "network.send"
	NetworkRecv    EventType = "network.recv"

	// Registry events (Windows only)
	RegistryRead   EventType = "registry.read"
	RegistryWrite  EventType = "registry.write"
	RegistryDelete EventType = "registry.delete"

	// Service events
	ServiceCreate EventType = "service.create"
	ServiceStart  EventType = "service.start"
	ServiceStop   EventType = "service.stop"
)

// Severity represents the threat level of an event or alert.
type Severity string

// Severity level constants ordered by escalation.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityWeight returns the numeric weight used in risk scoring.
func (s Severity) Weight() int {
	switch s {
	case SeverityLow:
		return 10
	case SeverityMedium:
		return 25
	case SeverityHigh:
		return 50
	case SeverityCritical:
		return 90
	default:
		return 0
	}
}

// ExitCode returns the CLI exit code for this severity level.
func (s Severity) ExitCode() int {
	switch s {
	case SeverityLow:
		return 10
	case SeverityMedium:
		return 11
	case SeverityHigh:
		return 12
	case SeverityCritical:
		return 13
	default:
		return 0
	}
}

// HostInfo contains identifying information about the host where an event occurred.
type HostInfo struct {
	ID        string   `json:"id"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	OSVersion string   `json:"os_version"`
	Arch      string   `json:"arch"`
	Tags      []string `json:"tags,omitempty"`
}

// ProcessData contains details about a process-related event.
type ProcessData struct {
	PID       int               `json:"pid"`
	PPID      int               `json:"ppid"`
	Name      string            `json:"name"`
	Path      string            `json:"path"`
	CmdLine   string            `json:"cmdline"`
	User      string            `json:"user"`
	UID       int               `json:"uid,omitempty"`
	GID       int               `json:"gid,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Hashes    map[string]string `json:"hashes,omitempty"`
	Parent    *ParentProcess    `json:"parent,omitempty"`
}

// ParentProcess contains information about the parent of a process.
type ParentProcess struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// NetworkData contains details about a network-related event.
type NetworkData struct {
	Protocol    string `json:"protocol"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     int    `json:"dst_port"`
	BytesSent   int64  `json:"bytes_sent,omitempty"`
	BytesRecv   int64  `json:"bytes_recv,omitempty"`
	ProcessPID  int    `json:"process_pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}

// FileData contains details about a file-related event.
type FileData struct {
	Path      string            `json:"path"`
	Name      string            `json:"name"`
	Size      int64             `json:"size,omitempty"`
	Hashes    map[string]string `json:"hashes,omitempty"`
	Owner     string            `json:"owner,omitempty"`
	OldPath   string            `json:"old_path,omitempty"` // For rename events
	Extension string            `json:"extension,omitempty"`
}

// RegistryData contains details about a registry-related event (Windows).
type RegistryData struct {
	Key       string `json:"key"`
	ValueName string `json:"value_name,omitempty"`
	ValueType string `json:"value_type,omitempty"`
	Value     string `json:"value,omitempty"`
	OldValue  string `json:"old_value,omitempty"`
}

// ServiceData contains details about a service-related event.
type ServiceData struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Path        string `json:"path,omitempty"`
	StartType   string `json:"start_type,omitempty"`
	Status      string `json:"status,omitempty"`
}

// EventData is a union type holding the typed payload of an event.
// Only one field will be populated depending on the EventType.
type EventData struct {
	Process  *ProcessData  `json:"process,omitempty"`
	Network  *NetworkData  `json:"network,omitempty"`
	File     *FileData     `json:"file,omitempty"`
	Registry *RegistryData `json:"registry,omitempty"`
	Service  *ServiceData  `json:"service,omitempty"`

	// Raw holds arbitrary key-value data for extensibility.
	Raw map[string]any `json:"raw,omitempty"`
}

// Event is the core data structure produced by all sensors.
// It represents a single observable action on a host.
type Event struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Host        HostInfo       `json:"host"`
	Type        EventType      `json:"type"`
	Severity    Severity       `json:"severity"`
	Sensor      string         `json:"sensor"`
	Data        EventData      `json:"data"`
	Enrichments map[string]any `json:"enrichments,omitempty"`
	ChainHash   string         `json:"chain_hash,omitempty"`
}

// String returns a human-readable summary of the event.
func (e Event) String() string {
	return fmt.Sprintf("[%s] %s %s on %s",
		e.Severity, e.Type, e.ID, e.Host.Hostname)
}

// JSON returns the event serialized as a JSON byte slice.
func (e Event) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// PrettyJSON returns the event serialized as indented JSON.
func (e Event) PrettyJSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
