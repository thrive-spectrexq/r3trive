package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type dummyStore struct{}

func (d *dummyStore) SaveEvent(ctx context.Context, evt event.Event) error { return nil }
func (d *dummyStore) GetEvent(ctx context.Context, id string) (event.Event, error) {
	return event.Event{}, nil
}
func (d *dummyStore) SaveEvents(ctx context.Context, events []event.Event) error { return nil }
func (d *dummyStore) QueryEvents(ctx context.Context, query storage.EventQuery) ([]event.Event, error) {
	return nil, nil
}
func (d *dummyStore) SaveAlert(ctx context.Context, alert event.Alert) error       { return nil }
func (d *dummyStore) SaveIncident(ctx context.Context, incident event.Incident) error { return nil }
func (d *dummyStore) GetIncident(ctx context.Context, id string) (event.Incident, error) {
	return event.Incident{}, nil
}
func (d *dummyStore) QueryIncidents(ctx context.Context, statuses []event.IncidentStatus) ([]event.Incident, error) {
	return nil, nil
}
func (d *dummyStore) UpdateIncidentStatus(ctx context.Context, id string, status event.IncidentStatus) error {
	return nil
}
func (d *dummyStore) SaveHost(ctx context.Context, host storage.Host) error { return nil }
func (d *dummyStore) GetHost(ctx context.Context, id string) (storage.Host, error) {
	return storage.Host{}, nil
}
func (d *dummyStore) ListHosts(ctx context.Context) ([]storage.Host, error) { return nil, nil }
func (d *dummyStore) SaveRule(ctx context.Context, rule storage.StoredRule) error { return nil }
func (d *dummyStore) GetRule(ctx context.Context, id string) (storage.StoredRule, error) {
	return storage.StoredRule{}, nil
}
func (d *dummyStore) ListRules(ctx context.Context, enabledOnly bool) ([]storage.StoredRule, error) {
	return nil, nil
}
func (d *dummyStore) DeleteRule(ctx context.Context, id string) error { return nil }
func (d *dummyStore) SaveIOC(ctx context.Context, ioc storage.IOCEntry) error { return nil }
func (d *dummyStore) QueryIOCs(ctx context.Context, iocType string, value string) ([]storage.IOCEntry, error) {
	return nil, nil
}
func (d *dummyStore) Close() error { return nil }

func TestNewServerRoutes(t *testing.T) {
	cfg := ServerConfig{
		Addr:   ":8080",
		APIKey: "testkey",
	}

	server := NewServer(cfg, &dummyStore{})
	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	// 1. Check Swagger route
	reqSwagger := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	recSwagger := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recSwagger, reqSwagger)
	if recSwagger.Code != http.StatusOK {
		t.Errorf("Swagger endpoint returned %d, want 200", recSwagger.Code)
	}

	// 2. Check OpenAPI route
	reqOpenAPI := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil)
	recOpenAPI := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recOpenAPI, reqOpenAPI)
	if recOpenAPI.Code != http.StatusOK {
		t.Errorf("OpenAPI JSON endpoint returned %d, want 200", recOpenAPI.Code)
	}

	// 3. Check health route
	reqHealth := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	recHealth := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Errorf("Health endpoint returned %d, want 200", recHealth.Code)
	}

	// 4. Check protected route without key returns 401
	reqEventsNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	recEventsNoAuth := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recEventsNoAuth, reqEventsNoAuth)
	if recEventsNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("Protected events endpoint returned %d without auth, want 401", recEventsNoAuth.Code)
	}

	// 5. Check protected route with key returns 200
	reqEventsAuth := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	reqEventsAuth.Header.Set("X-API-Key", "testkey")
	recEventsAuth := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recEventsAuth, reqEventsAuth)
	if recEventsAuth.Code != http.StatusOK {
		t.Errorf("Protected events endpoint returned %d with auth, want 200", recEventsAuth.Code)
	}
}
