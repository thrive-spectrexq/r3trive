// Package storage defines the interface for persistent event storage
// and provides a registry of available storage backends.
package storage

import (
	"context"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// EventQuery specifies filters for querying stored events.
type EventQuery struct {
	// Type filters by event type (e.g., "process.create").
	Type string
	// Severity filters by minimum severity level.
	Severity string
	// HostID filters by host identifier.
	HostID string
	// Since filters events after this timestamp.
	Since time.Time
	// Until filters events before this timestamp.
	Until time.Time
	// Limit caps the number of results.
	Limit int
	// Offset for pagination.
	Offset int
}

// Store is the interface for persistent event storage backends.
type Store interface {
	// SaveEvent persists a single event.
	SaveEvent(ctx context.Context, evt event.Event) error

	// GetEvent retrieves a specific event by ID.
	GetEvent(ctx context.Context, id string) (event.Event, error)

	// SaveEvents persists a batch of events atomically.
	SaveEvents(ctx context.Context, events []event.Event) error

	// QueryEvents retrieves events matching the query filters.
	QueryEvents(ctx context.Context, query EventQuery) ([]event.Event, error)

	// SaveAlert persists an alert record.
	SaveAlert(ctx context.Context, alert event.Alert) error

	// SaveIncident persists an incident record.
	SaveIncident(ctx context.Context, incident event.Incident) error

	// GetIncident retrieves a specific incident by ID.
	GetIncident(ctx context.Context, id string) (event.Incident, error)

	// QueryIncidents retrieves incidents matching the given statuses.
	QueryIncidents(ctx context.Context, statuses []event.IncidentStatus) ([]event.Incident, error)

	// UpdateIncidentStatus updates the status of an existing incident.
	UpdateIncidentStatus(ctx context.Context, id string, status event.IncidentStatus) error

	// Close releases all resources held by the store.
	Close() error
}
