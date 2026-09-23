package response

import (
	"context"
	"testing"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestEngine_RespondToIncident(t *testing.T) {
	engine := New(true) // Dry run mode enabled

	inc := event.Incident{
		ID:        "INC-001",
		RiskScore: 95,
		Severity:  event.SeverityCritical,
		Alerts: []event.Alert{
			{
				Event: event.Event{
					Data: event.EventData{
						Process: &event.ProcessData{PID: 1234},
					},
				},
			},
			{
				Event: event.Event{
					Data: event.EventData{
						Network: &event.NetworkData{DstIP: "8.8.8.8"},
					},
				},
			},
			{
				Event: event.Event{
					Data: event.EventData{
						File: &event.FileData{Path: `C:\temp\malware.exe`},
					},
				},
			},
		},
		ArtifactPaths: []string{`C:\temp\dropped.dll`},
	}

	results, err := engine.RespondToIncident(context.Background(), inc, 80)
	if err != nil {
		t.Fatalf("RespondToIncident failed: %v", err)
	}

	expectedActions := map[ActionType]bool{
		ActionIsolateHost: false,
		ActionKillProcess: false,
		ActionBlockIP:     false,
		ActionQuarantine:  false, // For both the FileData and the ArtifactPath
	}

	quarantineCount := 0

	for _, res := range results {
		expectedActions[res.Action] = true
		if res.Action == ActionQuarantine {
			quarantineCount++
		}
		if !res.Success {
			t.Errorf("Expected action %s to succeed in dry-run mode", res.Action)
		}
	}

	for action, executed := range expectedActions {
		if !executed {
			t.Errorf("Expected action %s to be executed", action)
		}
	}

	if quarantineCount != 2 {
		t.Errorf("Expected ActionQuarantine to be executed 2 times, got %d", quarantineCount)
	}
}

func TestEngine_RespondToIncident_BelowThreshold(t *testing.T) {
	engine := New(true)

	inc := event.Incident{
		ID:        "INC-002",
		RiskScore: 50,
		Severity:  event.SeverityMedium,
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

	results, err := engine.RespondToIncident(context.Background(), inc, 80)
	if err != nil {
		t.Fatalf("RespondToIncident failed: %v", err)
	}

	if len(results) > 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestKillProcess_ProtectedProcessProhibited(t *testing.T) {
	engine := New(true)

	// Attempting to kill lsass.exe or csrss.exe must be blocked by defensive guardrails
	protectedProcesses := []string{"lsass.exe", "csrss.exe", "services.exe", "systemd", "sshd"}
	for _, proc := range protectedProcesses {
		_, err := engine.Execute(context.Background(), ActionKillProcess, map[string]any{
			"pid":          500,
			"process_name": proc,
		})
		if err == nil {
			t.Errorf("expected guardrail error when trying to kill protected process %s, got nil", proc)
		}
	}
}

func TestRollbackActions_Validation(t *testing.T) {
	engine := New(true)

	// Test unblock_ip validation
	_, err := engine.Execute(context.Background(), ActionUnblockIP, map[string]any{"ip": "198.51.100.1"})
	if err != nil {
		t.Errorf("expected dry-run unblock_ip to succeed, got %v", err)
	}

	// Test unquarantine_file validation
	_, err = engine.Execute(context.Background(), ActionUnquarantine, map[string]any{"path": "C:\\temp\\file.txt"})
	if err != nil {
		t.Errorf("expected dry-run unquarantine_file to succeed, got %v", err)
	}

	// Test unisolate_host validation
	_, err = engine.Execute(context.Background(), ActionUnisolateHost, nil)
	if err != nil {
		t.Errorf("expected dry-run unisolate_host to succeed, got %v", err)
	}
}
