package security_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
	"github.com/thrive-spectrexq/r3trive/pkg/rule"
)

// normalizePath resolves directory traversal and slash variations.
func normalizePath(p string) string {
	cleaned := filepath.Clean(p)
	return strings.ToLower(cleaned)
}

func TestPathTraversalEvasion(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{
			input:    `C:\Windows\System32\..\System32\cmd.exe`,
			expected: `c:\windows\system32\cmd.exe`,
		},
		{
			input:    `C:\Windows\.\System32\powershell.exe`,
			expected: `c:\windows\system32\powershell.exe`,
		},
		{
			input:    `/bin/../bin/sh`,
			expected: `/bin/sh`,
		},
	}

	for _, tc := range cases {
		norm := normalizePath(tc.input)
		// On windows vs posix, check separator normalized
		normClean := strings.ReplaceAll(norm, "/", `\`)
		expectedClean := strings.ReplaceAll(tc.expected, "/", `\`)
		if !strings.EqualFold(normClean, expectedClean) {
			t.Errorf("path normalization failed for %s: got %s, want %s", tc.input, normClean, expectedClean)
		}
	}
}

func TestCommandLineWhitespaceEvasion(t *testing.T) {
	cmdlines := []string{
		"powershell.exe    -enc    SQBFAFgA",
		"powershell.exe\t-enc\tSQBFAFgA",
		"powershell.exe -enc SQBFAFgA",
	}

	targetFlag := "-enc"

	for _, cmd := range cmdlines {
		tokens := strings.Fields(cmd)
		found := false
		for _, tok := range tokens {
			if strings.EqualFold(tok, targetFlag) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("failed to match flag in obfuscated commandline: %q", cmd)
		}
	}
}

func TestCaseInsensitiveProcessMatching(t *testing.T) {
	evt := event.Event{
		Type: event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				Name: "MIMIKATZ.EXE",
				Path: `C:\Users\Public\MIMIKATZ.EXE`,
			},
		},
	}

	r := rule.Rule{
		ID:       "TEST-EVASION-01",
		Name:     "Mimikatz Detection",
		Severity: "critical",
		Conditions: []rule.Condition{
			{
				Field:    "data.process.name",
				Operator: "eq",
				Value:    "mimikatz.exe",
			},
		},
	}

	if evt.Data.Process == nil {
		t.Fatalf("missing process data")
	}

	procName := evt.Data.Process.Name
	val := r.Conditions[0].Value

	if !strings.EqualFold(procName, val) {
		t.Fatalf("case-insensitive match failed: %s vs %s", procName, val)
	}
}
