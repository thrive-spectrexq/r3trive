package yara

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// CliScanner uses the standard 'yara' executable to perform scans.
// It relies on the system having the 'yara' or 'yara64.exe' binary in the PATH.
type CliScanner struct {
	executablePath string
	rulesFilePath  string
	rulesLoaded    int
}

// NewCliScanner initializes a new CLI-based scanner.
func NewCliScanner() *CliScanner {
	// Try to find yara or yara64.exe in PATH
	var exe string
	if path, err := exec.LookPath("yara64.exe"); err == nil {
		exe = path
	} else if path, err := exec.LookPath("yara.exe"); err == nil {
		exe = path
	} else if path, err := exec.LookPath("yara"); err == nil {
		exe = path
	}

	return &CliScanner{
		executablePath: exe,
	}
}

// LoadRules concatenates all YARA rules in a directory into a temporary file for fast CLI execution.
func (s *CliScanner) LoadRules(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("YARA rules directory not found", "dir", dir)
			return nil
		}
		return err
	}

	var combinedRules bytes.Buffer
	count := 0

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yar" || ext == ".yara" {
			path := filepath.Join(dir, e.Name())
			content, err := os.ReadFile(path) // #nosec G304
			if err != nil {
				slog.Error("Failed to read YARA rule", "file", path, "err", err)
				continue
			}
			combinedRules.Write(content)
			combinedRules.WriteString("\n\n")
			count++
		}
	}

	if count == 0 {
		s.rulesLoaded = 0
		return nil
	}

	// Write to a temporary file
	tmpFile, err := os.CreateTemp("", "r3trive_yara_rules_*.yar")
	if err != nil {
		return fmt.Errorf("creating temp file for rules: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(combinedRules.Bytes()); err != nil {
		return fmt.Errorf("writing rules to temp file: %w", err)
	}

	s.rulesFilePath = tmpFile.Name()
	s.rulesLoaded = count
	slog.Info("Loaded YARA rules via CLI scanner", "count", count, "temp_file", s.rulesFilePath)
	return nil
}

func (s *CliScanner) ScanFile(ctx context.Context, path string) ([]Match, error) {
	if s.rulesFilePath == "" || s.rulesLoaded == 0 {
		return nil, nil // No rules loaded
	}

	return s.runYara(ctx, s.rulesFilePath, path)
}

func (s *CliScanner) ScanProcessMemory(ctx context.Context, pid int) ([]Match, error) {
	if s.rulesFilePath == "" || s.rulesLoaded == 0 {
		return nil, nil
	}

	return s.runYara(ctx, s.rulesFilePath, strconv.Itoa(pid))
}

	// runYara executes the yara CLI and parses its standard output.
func (s *CliScanner) runYara(ctx context.Context, ruleFile, target string) ([]Match, error) {
	// yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID
	// -m: print metadata
	// -g: print tags
	cmd := exec.CommandContext(ctx, s.executablePath, "-m", "-g", ruleFile, target) // #nosec G204
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("yara command returned error", "target", target, "err", err, "output", string(output))
	} else {
		slog.Info("yara command output", "target", target, "output", string(output))
	}

	return parseYaraOutput(string(output)), nil
}

// parseYaraOutput parses standard yara CLI output:
// RuleName [tag1,tag2] [meta_key="meta_value"] /path/to/file
func parseYaraOutput(output string) []Match {
	var matches []Match
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "error:") || strings.HasPrefix(line, "warning:") {
			continue
		}

		// Basic parsing
		// E.g., "MalwareRule [tag1,tag2] [author="John Doe", severity="high"] /tmp/file.exe"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}

		ruleName := parts[0]
		remainder := parts[1]

		match := Match{
			Rule: ruleName,
			Meta: make(map[string]interface{}),
		}

		// Extract tags (if any) - they are enclosed in the first [] after rule name
		if strings.HasPrefix(remainder, "[") {
			tagEnd := strings.Index(remainder, "]")
			if tagEnd != -1 {
				tagsStr := remainder[1:tagEnd]
				if tagsStr != "" {
					match.Tags = strings.Split(tagsStr, ",")
				}
				remainder = strings.TrimSpace(remainder[tagEnd+1:])
			}
		}

		// Extract metadata (if any) - enclosed in the next []
		if strings.HasPrefix(remainder, "[") {
			metaEnd := strings.Index(remainder, "]")
			if metaEnd != -1 {
				metaStr := remainder[1:metaEnd]
				// Parse key="value", key="value"
				metaPairs := strings.Split(metaStr, ",")
				for _, pair := range metaPairs {
					kv := strings.SplitN(pair, "=", 2)
					if len(kv) == 2 {
						key := strings.TrimSpace(kv[0])
						val := strings.TrimSpace(kv[1])
						val = strings.Trim(val, "\"") // Remove quotes
						match.Meta[key] = val
					}
				}
			}
		}

		matches = append(matches, match)
	}

	return matches
}
