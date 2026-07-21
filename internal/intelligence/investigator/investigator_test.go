package investigator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInvestigateBinary(t *testing.T) {
	ctx := context.Background()
	inv := New(nil, nil)

	// Create temporary binary sample file with suspicious strings
	tmpDir := t.TempDir()
	samplePath := filepath.Join(tmpDir, "test_suspicious.exe")

	content := []byte("MZ header sample SeDebugPrivilege HKCU\\Run 185.220.101.47 CreateRemoteThread")
	if err := os.WriteFile(samplePath, content, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	report, err := inv.InvestigateBinary(ctx, samplePath)
	if err != nil {
		t.Fatalf("InvestigateBinary error: %v", err)
	}

	if report.RiskScore == 0 {
		t.Errorf("expected non-zero risk score for suspicious binary")
	}

	if len(report.Findings) == 0 {
		t.Errorf("expected findings for suspicious binary")
	}

	if len(report.ATTACKTechniques) == 0 {
		t.Errorf("expected ATT&CK technique mappings")
	}
}

func TestInvestigateProcess(t *testing.T) {
	ctx := context.Background()
	inv := New(nil, nil)

	report, err := inv.InvestigateProcess(ctx, 1234)
	if err != nil {
		t.Fatalf("InvestigateProcess error: %v", err)
	}

	if report.Target != "PID:1234" {
		t.Errorf("expected target PID:1234, got %s", report.Target)
	}
}
