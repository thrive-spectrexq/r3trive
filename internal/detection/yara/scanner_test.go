package yara

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseYaraOutput(t *testing.T) {
	output := `
MalwareRule [tag1,tag2] [author="John Doe", severity="high"] /tmp/file.exe
SimpleRule /tmp/file.exe
RuleWithTags [tag1] /tmp/file.exe
RuleWithMeta [key="value"] /tmp/file.exe
`
	matches := parseYaraOutput(output)
	if len(matches) != 4 {
		t.Fatalf("expected 4 matches, got %d", len(matches))
	}

	// 1: MalwareRule
	if matches[0].Rule != "MalwareRule" {
		t.Errorf("expected MalwareRule, got %s", matches[0].Rule)
	}
	if len(matches[0].Tags) != 2 || matches[0].Tags[0] != "tag1" || matches[0].Tags[1] != "tag2" {
		t.Errorf("expected [tag1, tag2], got %v", matches[0].Tags)
	}
	if matches[0].Meta["author"] != "John Doe" || matches[0].Meta["severity"] != "high" {
		t.Errorf("expected author=John Doe, severity=high, got %v", matches[0].Meta)
	}

	// 2: SimpleRule
	if matches[1].Rule != "SimpleRule" {
		t.Errorf("expected SimpleRule, got %s", matches[1].Rule)
	}
	if len(matches[1].Tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(matches[1].Tags))
	}
	if len(matches[1].Meta) != 0 {
		t.Errorf("expected 0 meta, got %d", len(matches[1].Meta))
	}
}

func TestCliScanner_Integration(t *testing.T) {
	scanner := NewCliScanner()
	if scanner.executablePath == "" {
		t.Skip("yara CLI not installed in PATH, skipping integration test")
	}

	// Create temp dir for rules
	tmpDir, err := os.MkdirTemp("", "yara_test_rules")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ruleContent := `
rule TestRule {
    meta:
        description = "Test rule for integration"
    strings:
        $a = "Hello YARA"
    condition:
        $a
}
`
	rulePath := filepath.Join(tmpDir, "test.yar")
	if err := os.WriteFile(rulePath, []byte(ruleContent), 0644); err != nil {
		t.Fatalf("failed to write rule file: %v", err)
	}

	if err := scanner.LoadRules(tmpDir); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	// Create test file
	testFile := filepath.Join(tmpDir, "target.txt")
	if err := os.WriteFile(testFile, []byte("Some random text. Hello YARA! End of file."), 0644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	// Scan
	matches, err := scanner.ScanFile(context.Background(), testFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if matches[0].Rule != "TestRule" {
		t.Errorf("expected TestRule, got %s", matches[0].Rule)
	}
}
