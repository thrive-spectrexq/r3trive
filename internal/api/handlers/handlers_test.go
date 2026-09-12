package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type mockStore struct {
	events          []event.Event
	singleEvent     event.Event
	singleEventErr  error
	incidents       []event.Incident
	singleIncident  event.Incident
	singleIncErr    error
	hosts           []storage.Host
	singleHost      storage.Host
	singleHostErr   error
	rules           []storage.StoredRule
	singleRule      storage.StoredRule
	singleRuleErr   error
	iocs            []storage.IOCEntry
	saveErr         error
	deleteErr       error
	updateStatusErr error
}

func (m *mockStore) SaveEvent(ctx context.Context, evt event.Event) error { return m.saveErr }
func (m *mockStore) GetEvent(ctx context.Context, id string) (event.Event, error) {
	if m.singleEventErr != nil {
		return event.Event{}, m.singleEventErr
	}
	return m.singleEvent, nil
}
func (m *mockStore) SaveEvents(ctx context.Context, events []event.Event) error { return m.saveErr }
func (m *mockStore) QueryEvents(ctx context.Context, query storage.EventQuery) ([]event.Event, error) {
	if m.singleEventErr != nil {
		return nil, m.singleEventErr
	}
	return m.events, nil
}
func (m *mockStore) SaveAlert(ctx context.Context, alert event.Alert) error       { return m.saveErr }
func (m *mockStore) SaveIncident(ctx context.Context, incident event.Incident) error { return m.saveErr }
func (m *mockStore) GetIncident(ctx context.Context, id string) (event.Incident, error) {
	if m.singleIncErr != nil {
		return event.Incident{}, m.singleIncErr
	}
	return m.singleIncident, nil
}
func (m *mockStore) QueryIncidents(ctx context.Context, statuses []event.IncidentStatus) ([]event.Incident, error) {
	if m.singleIncErr != nil {
		return nil, m.singleIncErr
	}
	return m.incidents, nil
}
func (m *mockStore) UpdateIncidentStatus(ctx context.Context, id string, status event.IncidentStatus) error {
	return m.updateStatusErr
}
func (m *mockStore) SaveHost(ctx context.Context, host storage.Host) error { return m.saveErr }
func (m *mockStore) GetHost(ctx context.Context, id string) (storage.Host, error) {
	if m.singleHostErr != nil {
		return storage.Host{}, m.singleHostErr
	}
	return m.singleHost, nil
}
func (m *mockStore) ListHosts(ctx context.Context) ([]storage.Host, error) {
	if m.singleHostErr != nil {
		return nil, m.singleHostErr
	}
	return m.hosts, nil
}
func (m *mockStore) SaveRule(ctx context.Context, rule storage.StoredRule) error { return m.saveErr }
func (m *mockStore) GetRule(ctx context.Context, id string) (storage.StoredRule, error) {
	if m.singleRuleErr != nil {
		return storage.StoredRule{}, m.singleRuleErr
	}
	return m.singleRule, nil
}
func (m *mockStore) ListRules(ctx context.Context, enabledOnly bool) ([]storage.StoredRule, error) {
	if m.singleRuleErr != nil {
		return nil, m.singleRuleErr
	}
	return m.rules, nil
}
func (m *mockStore) DeleteRule(ctx context.Context, id string) error { return m.deleteErr }
func (m *mockStore) SaveIOC(ctx context.Context, ioc storage.IOCEntry) error { return m.saveErr }
func (m *mockStore) QueryIOCs(ctx context.Context, iocType string, value string) ([]storage.IOCEntry, error) {
	if m.saveErr != nil {
		return nil, m.saveErr
	}
	return m.iocs, nil
}
func (m *mockStore) Close() error { return nil }

func withURLParam(req *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestGetHealth(t *testing.T) {
	handler := GetHealth(&mockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed decoding health response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}
}

func TestEventsHandlers(t *testing.T) {
	store := &mockStore{
		events: []event.Event{
			{ID: "evt-1", Type: event.ProcessCreate},
		},
		singleEvent: event.Event{ID: "evt-1", Type: event.ProcessCreate},
	}

	// QueryEvents success
	hQuery := QueryEvents(store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?limit=10&type=process.create", nil)
	rec := httptest.NewRecorder()
	hQuery(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("QueryEvents status = %d, want 200", rec.Code)
	}

	// GetEvent success
	hGet := GetEvent(store)
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/events/evt-1", nil)
	reqGet = withURLParam(reqGet, "id", "evt-1")
	recGet := httptest.NewRecorder()
	hGet(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Errorf("GetEvent status = %d, want 200", recGet.Code)
	}

	// GetEvent not found
	storeErr := &mockStore{singleEventErr: errors.New("not found")}
	hGetErr := GetEvent(storeErr)
	reqGetErr := httptest.NewRequest(http.MethodGet, "/api/v1/events/missing", nil)
	reqGetErr = withURLParam(reqGetErr, "id", "missing")
	recGetErr := httptest.NewRecorder()
	hGetErr(recGetErr, reqGetErr)
	if recGetErr.Code != http.StatusNotFound {
		t.Errorf("GetEvent status = %d, want 404", recGetErr.Code)
	}
}

func TestAlertsHandlers(t *testing.T) {
	store := &mockStore{}

	// ListAlerts
	hList := ListAlerts(store)
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	recList := httptest.NewRecorder()
	hList(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Errorf("ListAlerts status = %d, want 200", recList.Code)
	}

	// AcknowledgeAlert
	hAck := AcknowledgeAlert(store)
	reqAck := httptest.NewRequest(http.MethodPut, "/api/v1/alerts/alt-1/acknowledge", nil)
	reqAck = withURLParam(reqAck, "id", "alt-1")
	recAck := httptest.NewRecorder()
	hAck(recAck, reqAck)
	if recAck.Code != http.StatusOK {
		t.Errorf("AcknowledgeAlert status = %d, want 200", recAck.Code)
	}
}

func TestRulesHandlers(t *testing.T) {
	store := &mockStore{
		rules: []storage.StoredRule{
			{ID: "rule-1", Name: "Detect Execution", Enabled: true},
		},
	}

	// ListRules
	hList := ListRules(store)
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/rules?enabled=true", nil)
	recList := httptest.NewRecorder()
	hList(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Errorf("ListRules status = %d, want 200", recList.Code)
	}

	// CreateRule valid
	hCreate := CreateRule(store)
	ruleBody := `{"id":"rule-2","name":"Detect Ransomware","severity":"critical","conditions":"field=ext"}`
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewBufferString(ruleBody))
	recCreate := httptest.NewRecorder()
	hCreate(recCreate, reqCreate)
	if recCreate.Code != http.StatusCreated {
		t.Errorf("CreateRule status = %d, want 201", recCreate.Code)
	}

	// CreateRule invalid
	reqCreateBad := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewBufferString(`{"id":""}`))
	recCreateBad := httptest.NewRecorder()
	hCreate(recCreateBad, reqCreateBad)
	if recCreateBad.Code != http.StatusBadRequest {
		t.Errorf("CreateRule bad request status = %d, want 400", recCreateBad.Code)
	}

	// UpdateRule
	hUpdate := UpdateRule(store)
	reqUpdate := httptest.NewRequest(http.MethodPut, "/api/v1/rules/rule-1", bytes.NewBufferString(ruleBody))
	reqUpdate = withURLParam(reqUpdate, "id", "rule-1")
	recUpdate := httptest.NewRecorder()
	hUpdate(recUpdate, reqUpdate)
	if recUpdate.Code != http.StatusOK {
		t.Errorf("UpdateRule status = %d, want 200", recUpdate.Code)
	}

	// DeleteRule
	hDelete := DeleteRule(store)
	reqDelete := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/rule-1", nil)
	reqDelete = withURLParam(reqDelete, "id", "rule-1")
	recDelete := httptest.NewRecorder()
	hDelete(recDelete, reqDelete)
	if recDelete.Code != http.StatusNoContent {
		t.Errorf("DeleteRule status = %d, want 204", recDelete.Code)
	}
}

func TestHostsHandlers(t *testing.T) {
	store := &mockStore{
		hosts:      []storage.Host{{ID: "host-1", Hostname: "srv1"}},
		singleHost: storage.Host{ID: "host-1", Hostname: "srv1"},
	}

	hList := ListHosts(store)
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	recList := httptest.NewRecorder()
	hList(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Errorf("ListHosts status = %d, want 200", recList.Code)
	}

	hGet := GetHost(store)
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/host-1", nil)
	reqGet = withURLParam(reqGet, "id", "host-1")
	recGet := httptest.NewRecorder()
	hGet(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Errorf("GetHost status = %d, want 200", recGet.Code)
	}

	hReg := RegisterHost(store)
	reqReg := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBufferString(`{"id":"h2","hostname":"srv2"}`))
	recReg := httptest.NewRecorder()
	hReg(recReg, reqReg)
	if recReg.Code != http.StatusCreated {
		t.Errorf("RegisterHost status = %d, want 201", recReg.Code)
	}
}

func TestIncidentsHandlers(t *testing.T) {
	store := &mockStore{
		incidents: []event.Incident{
			{ID: "inc-1", Status: event.IncidentStatusOpen},
		},
		singleIncident: event.Incident{ID: "inc-1", Status: event.IncidentStatusOpen},
	}

	hList := ListIncidents(store)
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?status=open", nil)
	recList := httptest.NewRecorder()
	hList(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Errorf("ListIncidents status = %d, want 200", recList.Code)
	}

	hGet := GetIncident(store)
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc-1", nil)
	reqGet = withURLParam(reqGet, "id", "inc-1")
	recGet := httptest.NewRecorder()
	hGet(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Errorf("GetIncident status = %d, want 200", recGet.Code)
	}

	hStatus := UpdateIncidentStatus(store)
	reqStatus := httptest.NewRequest(http.MethodPut, "/api/v1/incidents/inc-1/status", bytes.NewBufferString(`{"status":"contained"}`))
	reqStatus = withURLParam(reqStatus, "id", "inc-1")
	recStatus := httptest.NewRecorder()
	hStatus(recStatus, reqStatus)
	if recStatus.Code != http.StatusOK {
		t.Errorf("UpdateIncidentStatus status = %d, want 200", recStatus.Code)
	}
}

func TestIOCsHandlers(t *testing.T) {
	store := &mockStore{
		iocs: []storage.IOCEntry{
			{ID: "ioc-1", Type: "ip", Value: "1.2.3.4", CreatedAt: time.Now()},
		},
	}

	hQuery := QueryIOCs(store)
	reqQuery := httptest.NewRequest(http.MethodGet, "/api/v1/iocs?type=ip&value=1.2.3.4", nil)
	recQuery := httptest.NewRecorder()
	hQuery(recQuery, reqQuery)
	if recQuery.Code != http.StatusOK {
		t.Errorf("QueryIOCs status = %d, want 200", recQuery.Code)
	}

	hAdd := AddIOC(store)
	reqAdd := httptest.NewRequest(http.MethodPost, "/api/v1/iocs", bytes.NewBufferString(`{"id":"ioc-2","type":"domain","value":"evil.com"}`))
	recAdd := httptest.NewRecorder()
	hAdd(recAdd, reqAdd)
	if recAdd.Code != http.StatusCreated {
		t.Errorf("AddIOC status = %d, want 201", recAdd.Code)
	}
}
