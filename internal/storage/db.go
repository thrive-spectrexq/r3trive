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

// Host represents a managed endpoint.
type Host struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	IPAddress string    `json:"ip_address,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	AgentVer  string    `json:"agent_ver,omitempty"`
	Status    string    `json:"status"`
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// StoredRule represents a persisted correlation rule.
type StoredRule struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Severity        string    `json:"severity"`
	Confidence      float64   `json:"confidence"`
	Enabled         bool      `json:"enabled"`
	Conditions      string    `json:"conditions"`
	ATTACKTactic    string    `json:"attack_tactic,omitempty"`
	ATTACKTechnique string    `json:"attack_technique,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// IOCEntry represents an Indicator of Compromise.
type IOCEntry struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Source    string    `json:"source,omitempty"`
	Severity  string    `json:"severity"`
	Tags      []string  `json:"tags,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	CreatedAt time.Time `json:"created_at"`
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

	// Host management
	SaveHost(ctx context.Context, host Host) error
	GetHost(ctx context.Context, id string) (Host, error)
	ListHosts(ctx context.Context) ([]Host, error)

	// Rule management
	SaveRule(ctx context.Context, rule StoredRule) error
	GetRule(ctx context.Context, id string) (StoredRule, error)
	ListRules(ctx context.Context, enabledOnly bool) ([]StoredRule, error)
	DeleteRule(ctx context.Context, id string) error

	// IOC management
	SaveIOC(ctx context.Context, ioc IOCEntry) error
	QueryIOCs(ctx context.Context, iocType string, value string) ([]IOCEntry, error)

	// Close releases all resources held by the store.
	Close() error
}
