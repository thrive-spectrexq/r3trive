package sigma

import (
	"testing"
)

func TestSigmaTranspiler(t *testing.T) {
	sigmaContent := `
title: PowerShell Encoded Command Execution
id: 5a4325a7-9e6e-4731-bbdc-e87f54c12658
description: Detects base64 encoded command execution in PowerShell
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains: -enc
  condition: selection
`

	sr, err := ParseRule([]byte(sigmaContent))
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}
	if sr.Title != "PowerShell Encoded Command Execution" {
		t.Errorf("unexpected title: %s", sr.Title)
	}

	transpiler := NewTranspiler()
	r3Rule, err := transpiler.Transpile(sr)
	if err != nil {
		t.Fatalf("Transpile failed: %v", err)
	}
	if r3Rule.Severity != "high" {
		t.Errorf("expected high severity, got %s", r3Rule.Severity)
	}
	if len(r3Rule.Conditions) == 0 {
		t.Errorf("expected conditions in transpiled rule")
	}
}

func TestSigmaFilterAndParentMapping(t *testing.T) {
	sigmaContent := `
title: Suspicious Child of Word
id: 11111111-2222-3333-4444-555555555555
description: Detects suspicious child process spawned by Microsoft Word
level: critical
tags:
  - attack.execution
  - attack.t1204.002
detection:
  selection:
    ParentImage|endswith: winword.exe
    Image|endswith: cmd.exe
  filter:
    CommandLine|contains: benign_addon
  condition: selection and not filter
`

	sr, err := ParseRule([]byte(sigmaContent))
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}

	transpiler := NewTranspiler()
	r3Rule, err := transpiler.Transpile(sr)
	if err != nil {
		t.Fatalf("Transpile failed: %v", err)
	}

	foundParent := false
	foundNegatedFilter := false
	for _, cond := range r3Rule.Conditions {
		if cond.Field == "data.process.parent.name" {
			foundParent = true
			if cond.Operator != "endsWith" || cond.Value != "winword.exe" {
				t.Errorf("unexpected parent condition: %+v", cond)
			}
		}
		if cond.Field == "data.process.cmdline" {
			if cond.Operator == "not_contains" && cond.Value == "benign_addon" {
				foundNegatedFilter = true
			}
		}
	}

	if !foundParent {
		t.Errorf("expected mapped field data.process.parent.name not found in conditions: %+v", r3Rule.Conditions)
	}
	if !foundNegatedFilter {
		t.Errorf("expected negated filter condition (not_contains) not found: %+v", r3Rule.Conditions)
	}
}
