// Package sensor defines the common interface for all platform-specific
// event collection modules (sensors). Each sensor produces events that
// conform to the pkg/event.Event schema.
package sensor

import (
	"context"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Platform represents a supported operating system.
type Platform string

// Supported platforms.
const (
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "darwin"
)

// SensorHealth represents the operational status of a sensor.
type SensorHealth struct {
	// Healthy indicates whether the sensor is functioning normally.
	Healthy bool `json:"healthy"`
	// Status is a human-readable status message.
	Status string `json:"status"`
	// EventsCollected is the total number of events this sensor has produced.
	EventsCollected int64 `json:"events_collected"`
	// LastEventTime is the timestamp of the last event.
	LastEventTime string `json:"last_event_time,omitempty"`
	// ErrorCount is the number of errors encountered.
	ErrorCount int64 `json:"error_count"`
}

// Sensor is the interface implemented by all platform-specific event
// collection modules. Sensors run in their own goroutine and push
// events into the provided channel.
type Sensor interface {
	// Name returns the sensor's unique identifier.
	Name() string

	// Platform returns the platforms this sensor supports.
	Platform() []Platform

	// Start begins event collection. Events are sent to the provided channel.
	// The sensor must respect context cancellation and stop cleanly.
	// Start blocks until the context is cancelled or an unrecoverable error occurs.
	Start(ctx context.Context, ch chan<- event.Event) error

	// Stop performs graceful shutdown and resource cleanup.
	Stop() error

	// Health returns the current health status of the sensor.
	Health() SensorHealth
}
