package rule

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRuleValid(t *testing.T) {
	yamlContent := `
id: R3T-PROC-001
name: Suspicious Process Execution
description: Detects execution of cmd.exe via PowerShell
type: atomic
severity: high
confidence: 0.85
conditions:
  - field: process.name
    operator: eq
    value: cmd.exe
  - field: process.parent.name
    operator: eq
    value: powershell.exe
attack_tactic: Execution
attack_technique: T1059
tags:
  - windows
  - execution
`

	r, err := ParseRule([]byte(yamlContent))
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}

	if r.ID != "R3T-PROC-001" || r.Name != "Suspicious Process Execution" {
		t.Errorf("unexpected rule fields: %+v", r)
	}

	if err := r.Validate(); err != nil {
		t.Errorf("expected valid rule, got error: %v", err)
	}

	if len(r.Conditions) != 2 {
		t.Errorf("expected 2 conditions, got %d", len(r.Conditions))
	}
}

func TestParseRuleValidationFailures(t *testing.T) {
	missingID := &Rule{
		Name: "Missing ID Rule",
		Conditions: []Condition{
			{Field: "process.name", Operator: "eq", Value: "whoami.exe"},
		},
	}
	if err := missingID.Validate(); err == nil {
		t.Error("expected error for missing ID, got nil")
	}

	missingName := &Rule{
		ID: "R3T-TEST-001",
		Conditions: []Condition{
			{Field: "process.name", Operator: "eq", Value: "whoami.exe"},
		},
	}
	if err := missingName.Validate(); err == nil {
		t.Error("expected error for missing Name, got nil")
	}

	missingConditions := &Rule{
		ID:   "R3T-TEST-002",
		Name: "No Conditions Rule",
	}
	if err := missingConditions.Validate(); err == nil {
		t.Error("expected error for missing Conditions, got nil")
	}
}

func TestParseRuleFile(t *testing.T) {
	tempDir := t.TempDir()
	rulePath := filepath.Join(tempDir, "test_rule.yaml")

	content := `
id: R3T-FILE-001
name: Ransomware Extension Created
description: Detects encrypted extension
type: atomic
severity: critical
conditions:
  - field: file.extension
    operator: eq
    value: .locked
`
	if err := os.WriteFile(rulePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing temp rule file: %v", err)
	}

	r, err := ParseRuleFile(rulePath)
	if err != nil {
		t.Fatalf("ParseRuleFile failed: %v", err)
	}

	if r.ID != "R3T-FILE-001" {
		t.Errorf("expected ID R3T-FILE-001, got %s", r.ID)
	}

	// Non-existent file
	if _, err := ParseRuleFile(filepath.Join(tempDir, "non_existent.yaml")); err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}
