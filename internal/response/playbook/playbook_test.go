package playbook

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/response"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type MockExecutor struct {
	Executed []struct {
		Action response.ActionType
		Params map[string]any
	}
	FailAction response.ActionType
}

func (m *MockExecutor) Execute(ctx context.Context, action response.ActionType, params map[string]any) (response.ActionResult, error) {
	m.Executed = append(m.Executed, struct {
		Action response.ActionType
		Params map[string]any
	}{Action: action, Params: params})

	if action == m.FailAction {
		return response.ActionResult{
			Action:     action,
			Success:    false,
			Message:    "mock failure",
			Timestamp:  time.Now().UTC(),
			Reversible: false,
		}, fmt.Errorf("mock error for %s", action)
	}

	reversible := action == response.ActionBlockIP || action == response.ActionIsolateHost || action == response.ActionQuarantine
	return response.ActionResult{
		Action:     action,
		Success:    true,
		Message:    fmt.Sprintf("mock success for %s", action),
		Timestamp:  time.Now().UTC(),
		Reversible: reversible,
	}, nil
}

func TestParseYAMLAndValidate(t *testing.T) {
	yamlData := `
id: PB-TEST-001
name: Test Ransomware Playbook
description: Automated test playbook
trigger:
  incident_type: ransomware
  risk_score_gte: 80
  severity_gte: high
steps:
  - name: Kill Process
    action: kill_process
    params:
      pid: "$.incident.primary_pid"
    on_failure: continue
  - name: Isolate Host
    action: isolate_host
    params:
      host_id: "$.incident.host_id"
      message: "Ransomware detected on {{ $.incident.host_id }}"
    on_failure: abort
`

	pb, err := ParseYAML([]byte(yamlData))
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	if pb.ID != "PB-TEST-001" {
		t.Errorf("expected ID PB-TEST-001, got %s", pb.ID)
	}

	if len(pb.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(pb.Steps))
	}
}

func TestPlaybookMatching(t *testing.T) {
	pb := &Playbook{
		ID:   "PB-001",
		Name: "High Risk Ransomware",
		Trigger: PlaybookTrigger{
			IncidentType: "ransomware",
			RiskScoreGTE: 80,
			SeverityGTE:  event.SeverityHigh,
		},
		Steps: []Step{
			{Name: "Kill", Action: response.ActionKillProcess},
		},
	}

	incidentMatch := event.Incident{
		ID:          "INC-001",
		Title:       "Ransomware activity detected",
		Description: "Suspicious volume shadow copy deletion",
		RiskScore:   90,
		Severity:    event.SeverityCritical,
	}

	if !pb.Matches(incidentMatch) {
		t.Errorf("expected incident to match playbook trigger")
	}

	incidentLowRisk := event.Incident{
		ID:          "INC-002",
		Title:       "Ransomware activity detected",
		Description: "Suspicious volume shadow copy deletion",
		RiskScore:   50,
		Severity:    event.SeverityLow,
	}

	if pb.Matches(incidentLowRisk) {
		t.Errorf("expected low risk incident NOT to match playbook trigger")
	}
}

func TestEvaluator(t *testing.T) {
	incident := event.Incident{
		ID:        "INC-100",
		Title:     "Credential Access",
		RiskScore: 95,
		Severity:  event.SeverityCritical,
		HostIDs:   []string{"host-prod-01"},
		ArtifactPaths: []string{
			"/tmp/mimikatz.exe",
		},
		Alerts: []event.Alert{
			{
				Event: event.Event{
					Data: event.EventData{
						Process: &event.ProcessData{
							PID:  4821,
							Name: "powershell.exe",
						},
						Network: &event.NetworkData{
							DstIP: "185.220.101.47",
						},
					},
				},
			},
		},
	}

	params := map[string]any{
		"pid":     "$.incident.primary_pid",
		"host_id": "$.incident.host_id",
		"ip":      "$.incident.primary_ip",
		"title":   "Alert: {{ $.incident.title }} on {{ $.incident.host_id }}",
	}

	evaluated := EvaluateParams(params, incident)

	if evaluated["pid"] != 4821 {
		t.Errorf("expected pid 4821, got %v", evaluated["pid"])
	}
	if evaluated["host_id"] != "host-prod-01" {
		t.Errorf("expected host_id host-prod-01, got %v", evaluated["host_id"])
	}
	if evaluated["ip"] != "185.220.101.47" {
		t.Errorf("expected ip 185.220.101.47, got %v", evaluated["ip"])
	}
	if evaluated["title"] != "Alert: Credential Access on host-prod-01" {
		t.Errorf("expected title 'Alert: Credential Access on host-prod-01', got '%v'", evaluated["title"])
	}
}

func TestEngineExecution(t *testing.T) {
	engine := NewEngine(false)

	pb := &Playbook{
		ID:   "PB-RUN-001",
		Name: "Test Run",
		Trigger: PlaybookTrigger{
			RiskScoreGTE: 50,
		},
		Steps: []Step{
			{
				Name:   "Kill process",
				Action: response.ActionKillProcess,
				Params: map[string]any{"pid": "$.incident.primary_pid"},
			},
			{
				Name:   "Isolate host",
				Action: response.ActionIsolateHost,
				Params: map[string]any{"host_id": "$.incident.host_id"},
			},
		},
	}

	if err := engine.Register(pb); err != nil {
		t.Fatalf("failed to register playbook: %v", err)
	}

	incident := event.Incident{
		ID:        "INC-555",
		RiskScore: 75,
		HostIDs:   []string{"host-01"},
		Alerts: []event.Alert{
			{
				Event: event.Event{
					Data: event.EventData{
						Process: &event.ProcessData{PID: 1234},
					},
				},
			},
		},
	}

	mockExec := &MockExecutor{}
	results, err := engine.EvaluateAndExecute(context.Background(), incident, mockExec)
	if err != nil {
		t.Fatalf("EvaluateAndExecute failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if !res.Success {
		t.Errorf("expected playbook execution to succeed")
	}

	if len(res.StepResults) != 2 {
		t.Errorf("expected 2 step results, got %d", len(res.StepResults))
	}

	if len(res.RollbackPlan) != 1 {
		t.Errorf("expected 1 rollback item (for isolate_host), got %d", len(res.RollbackPlan))
	}
}

func TestEngineOnFailureAbort(t *testing.T) {
	engine := NewEngine(false)

	pb := &Playbook{
		ID:   "PB-FAIL-001",
		Name: "Test Failure",
		Trigger: PlaybookTrigger{
			RiskScoreGTE: 50,
		},
		Steps: []Step{
			{
				Name:      "Failing Step",
				Action:    response.ActionKillProcess,
				OnFailure: OnFailureAbort,
			},
			{
				Name:   "Should Not Run",
				Action: response.ActionIsolateHost,
			},
		},
	}

	_ = engine.Register(pb)

	incident := event.Incident{
		ID:        "INC-999",
		RiskScore: 90,
	}

	mockExec := &MockExecutor{FailAction: response.ActionKillProcess}
	results, err := engine.EvaluateAndExecute(context.Background(), incident, mockExec)
	if err != nil {
		t.Logf("got expected error on abort: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result object, got %d", len(results))
	}

	res := results[0]
	if res.Success {
		t.Errorf("expected execution to fail")
	}

	if len(res.StepResults) != 1 {
		t.Errorf("expected only 1 step executed before abort, got %d", len(res.StepResults))
	}
}

func TestLoadDir(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "playbook_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	pbYAML := `
id: PB-DIR-001
name: Dir Playbook Test
trigger:
  risk_score_gte: 10
steps:
  - name: Step 1
    action: kill_process
`
	filePath := filepath.Join(tempDir, "test_playbook.yaml")
	if err := os.WriteFile(filePath, []byte(pbYAML), 0644); err != nil {
		t.Fatalf("failed to write test playbook: %v", err)
	}

	engine := NewEngine(false)
	if err := engine.LoadDir(tempDir); err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}

	pbs := engine.ListPlaybooks()
	if len(pbs) != 1 {
		t.Fatalf("expected 1 loaded playbook from dir, got %d", len(pbs))
	}
	if pbs[0].ID != "PB-DIR-001" {
		t.Errorf("expected PB-DIR-001, got %s", pbs[0].ID)
	}
}
