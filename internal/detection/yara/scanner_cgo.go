//go:build cgo

package yara

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hillu/go-yara/v4"
)

// CgoScanner implements the Scanner interface using the native C YARA library.
type CgoScanner struct {
	compiler *yara.Compiler
	rules    *yara.Rules
	mu       sync.RWMutex
}

// newCgoScanner creates a new native CGO YARA scanner.
func newCgoScanner() (*CgoScanner, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create YARA compiler: %w", err)
	}

	return &CgoScanner{
		compiler: compiler,
	}, nil
}

// LoadRules compiles all YARA rules from the specified directory.
func (s *CgoScanner) LoadRules(dir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
		if e.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yar" || ext == ".yara" {
			path := filepath.Join(dir, e.Name())
			f, fileErr := os.Open(path)
			if fileErr != nil {
				slog.Error("Failed to open YARA rule", "file", path, "err", fileErr)
				continue
			}

			if err := s.compiler.AddFile(f, e.Name()); err != nil {
				slog.Error("Failed to compile YARA rule", "file", path, "err", err)
				f.Close()
				continue
			}
			f.Close()
			count++
		}
	}

	// Retrieve compiled rules
	rules, err := s.compiler.GetRules()
	if err != nil {
		return fmt.Errorf("failed to get compiled rules: %w", err)
	}

	s.rules = rules
	slog.Info("Loaded native YARA rules (CGO)", "count", count)
	return nil
}

// ScanFile scans a file on disk.
func (s *CgoScanner) ScanFile(ctx context.Context, path string) ([]Match, error) {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	if rules == nil {
		return nil, nil
	}

	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return nil, fmt.Errorf("creating scanner: %w", err)
	}

	var m yara.MatchRules
	err = scanner.SetCallback(&m).ScanFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanning file: %w", err)
	}

	return s.convertMatches(m), nil
}

// ScanProcessMemory scans a running process.
func (s *CgoScanner) ScanProcessMemory(ctx context.Context, pid int) ([]Match, error) {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	if rules == nil {
		return nil, nil
	}

	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return nil, fmt.Errorf("creating scanner: %w", err)
	}

	var m yara.MatchRules
	err = scanner.SetCallback(&m).ScanProc(pid)
	if err != nil {
		return nil, fmt.Errorf("scanning process: %w", err)
	}

	return s.convertMatches(m), nil
}

func (s *CgoScanner) convertMatches(m yara.MatchRules) []Match {
	results := make([]Match, 0, len(m))
	for _, match := range m {
		tags := make([]string, len(match.Tags))
		copy(tags, match.Tags)

		meta := make(map[string]interface{})
		for _, m := range match.Metas {
			meta[m.Identifier] = m.Value
		}

		results = append(results, Match{
			Rule:      match.Rule,
			Namespace: match.Namespace,
			Tags:      tags,
			Meta:      meta,
		})
	}
	return results
}
