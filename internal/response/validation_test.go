package response

import (
	"context"
	"testing"
)

func TestKillProcess_NegativePID(t *testing.T) {
	engine := New(true) // dry-run
	_, err := engine.Execute(context.Background(), ActionKillProcess, map[string]any{"pid": -1})
	if err == nil {
		t.Fatal("expected error for negative PID, got nil")
	}
	if want := "invalid pid: -1 (must be positive)"; err.Error() != want {
		t.Errorf("expected error %q, got %q", want, err.Error())
	}
}

func TestKillProcess_ZeroPID(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionKillProcess, map[string]any{"pid": 0})
	if err == nil {
		t.Fatal("expected error for zero PID, got nil")
	}
}

func TestKillProcess_Float64PID(t *testing.T) {
	engine := New(true)
	result, err := engine.Execute(context.Background(), ActionKillProcess, map[string]any{"pid": float64(1234)})
	if err != nil {
		t.Fatalf("unexpected error for float64 PID: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success in dry-run mode, got failure: %s", result.Message)
	}
}

func TestKillProcess_MissingPID(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionKillProcess, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing pid, got nil")
	}
}

func TestKillProcess_InvalidPIDType(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionKillProcess, map[string]any{"pid": "notanumber"})
	if err == nil {
		t.Fatal("expected error for string PID, got nil")
	}
}

func TestBlockIP_InvalidFormat(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionBlockIP, map[string]any{"ip": "not-an-ip"})
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}

func TestBlockIP_EmptyString(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionBlockIP, map[string]any{"ip": ""})
	if err == nil {
		t.Fatal("expected error for empty IP, got nil")
	}
}

func TestBlockIP_MissingParam(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionBlockIP, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing ip param, got nil")
	}
}

func TestQuarantineFile_MissingPath(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionQuarantine, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
}

func TestQuarantineFile_InvalidPathType(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionQuarantine, map[string]any{"path": 12345})
	if err == nil {
		t.Fatal("expected error for integer path, got nil")
	}
}

func TestUnknownActionType(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionType("does_not_exist"), map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown action, got nil")
	}
}

func TestDryRunBlockIP_ValidIPv4(t *testing.T) {
	engine := New(true)
	result, err := engine.Execute(context.Background(), ActionBlockIP, map[string]any{"ip": "192.168.1.1"})
	if err != nil {
		t.Fatalf("unexpected error for valid IPv4: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success in dry-run mode")
	}
}

func TestDryRunBlockIP_ValidIPv6(t *testing.T) {
	engine := New(true)
	result, err := engine.Execute(context.Background(), ActionBlockIP, map[string]any{"ip": "::1"})
	if err != nil {
		t.Fatalf("unexpected error for valid IPv6: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success in dry-run mode")
	}
}

func TestKillProcess_PID1Prohibited(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionKillProcess, map[string]any{"pid": 1})
	if err == nil {
		t.Fatalf("expected guardrail error for PID 1, got nil")
	}
}

func TestBlockIP_LocalhostProhibited(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionBlockIP, map[string]any{"ip": "127.0.0.1"})
	if err == nil {
		t.Fatalf("expected guardrail error for blocking 127.0.0.1, got nil")
	}
}

func TestIsolateHost_LocalhostProhibited(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionIsolateHost, map[string]any{"target": "127.0.0.1"})
	if err == nil {
		t.Fatalf("expected guardrail error for isolating 127.0.0.1, got nil")
	}
}

func TestEngine_AuditLogging(t *testing.T) {
	engine := New(true)
	_, err := engine.Execute(context.Background(), ActionBlockIP, map[string]any{"ip": "198.51.100.25"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	audit := engine.AuditLog()
	if len(audit) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(audit))
	}
	if audit[0].Action != ActionBlockIP || !audit[0].Success || !audit[0].DryRun {
		t.Errorf("audit record mismatch: %+v", audit[0])
	}
}

