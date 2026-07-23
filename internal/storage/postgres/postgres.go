package postgres

import (
	"context"
	"fmt"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Store implements storage.Store for PostgreSQL enterprise fleet deployments.
type Store struct {
	dsn string
}

// New creates a new PostgreSQL storage backend.
func New(dsn string) (*Store, error) {
	if dsn == "" {
		return nil, fmt.Errorf("empty PostgreSQL connection DSN")
	}
	return nil, fmt.Errorf("postgres storage driver is not yet supported in this build; please use 'sqlite' storage driver")
}

func (s *Store) SaveEvent(ctx context.Context, evt event.Event) error {
	return fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) GetEvent(ctx context.Context, id string) (event.Event, error) {
	return event.Event{}, fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) SaveEvents(ctx context.Context, events []event.Event) error {
	return fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) QueryEvents(ctx context.Context, query storage.EventQuery) ([]event.Event, error) {
	return nil, fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) SaveAlert(ctx context.Context, alert event.Alert) error {
	return fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) SaveIncident(ctx context.Context, incident event.Incident) error {
	return fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) GetIncident(ctx context.Context, id string) (event.Incident, error) {
	return event.Incident{}, fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) QueryIncidents(ctx context.Context, statuses []event.IncidentStatus) ([]event.Incident, error) {
	return nil, fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) UpdateIncidentStatus(ctx context.Context, id string, status event.IncidentStatus) error {
	return fmt.Errorf("postgres storage driver not supported")
}

func (s *Store) Close() error {
	return nil
}

var _ storage.Store = (*Store)(nil)
