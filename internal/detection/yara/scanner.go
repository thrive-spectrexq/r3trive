package yara

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Scanner represents an engine capable of scanning files or memory using YARA rules.
type Scanner interface {
	// ScanFile scans a file on disk and returns matched rules.
	ScanFile(ctx context.Context, path string) ([]Match, error)
	// ScanProcessMemory scans a running process's memory.
	ScanProcessMemory(ctx context.Context, pid int) ([]Match, error)
	// LoadRules loads YARA rule files from a directory.
	LoadRules(dir string) error
}

// Match represents a single YARA rule match.
type Match struct {
	Rule      string
	Namespace string
	Tags      []string
	Meta      map[string]interface{}
}

// MockScanner provides a simulated YARA scanning interface for systems without CGO enabled.
// It bypasses the need for libyara compilation on Windows while fulfilling the pipeline contract.
type MockScanner struct {
	rulesLoaded int
}

// NewMockScanner initializes a new mock scanner.
func NewMockScanner() *MockScanner {
	return &MockScanner{}
}

func (s *MockScanner) LoadRules(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("YARA rules directory not found", "dir", dir)
			return nil
		}
		return err
	}

	count := 0
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yar") || strings.HasSuffix(e.Name(), ".yara")) {
			count++
		}
	}
	s.rulesLoaded = count
	slog.Info("Loaded mock YARA rules", "count", count, "dir", dir)
	return nil
}

func (s *MockScanner) ScanFile(ctx context.Context, path string) ([]Match, error) {
	// Simulate scan latency
	time.Sleep(50 * time.Millisecond)

	// In a real implementation, we would pass the file to libyara here.
	// We'll mock a detection for demonstration if the file has "eicar" in the name.
	if strings.Contains(strings.ToLower(path), "eicar") {
		return []Match{
			{
				Rule:      "EICAR_Test_File",
				Namespace: "default",
				Tags:      []string{"test", "av"},
				Meta: map[string]interface{}{
					"description": "Standard AV test file",
					"severity":    "high",
				},
			},
		}, nil
	}

	return nil, nil // No matches
}

func (s *MockScanner) ScanProcessMemory(ctx context.Context, pid int) ([]Match, error) {
	// Simulate scan latency
	time.Sleep(100 * time.Millisecond)
	
	// Mock: no matches
	return nil, nil
}

// Ensure MockScanner implements Scanner
var _ Scanner = (*MockScanner)(nil)
