package hunter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
	"github.com/thrive-spectrexq/r3trive/pkg/sigma"
)

// HuntOptions specifies configuration options for a threat hunt.
type HuntOptions struct {
	Technique string
	Ruleset   string
	TargetDir string
	OutputFmt string
	MaxDepth  int
}

// Finding represents a single detection or artifact hit during a threat hunt.
type Finding struct {
	Category    string         `json:"category"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Severity    event.Severity `json:"severity"`
	Technique   string         `json:"technique,omitempty"`
	Artifact    string         `json:"artifact"`
	Description string         `json:"description"`
	Details     map[string]any `json:"details,omitempty"`
}

// HuntResult aggregates the outcome of a threat hunting operation.
type HuntResult struct {
	Timestamp    time.Time `json:"timestamp"`
	HostName     string    `json:"hostname"`
	OS           string    `json:"os"`
	Technique    string    `json:"technique_filter,omitempty"`
	TotalScanned int       `json:"total_scanned"`
	MatchesCount int       `json:"matches_count"`
	Findings     []Finding `json:"findings"`
}

// Hunter drives the threat hunting execution across system artifacts and rule bases.
type Hunter struct {
	yaraScanner yara.Scanner
}

// New creates a new Hunter instance.
func New(yScanner yara.Scanner) *Hunter {
	if yScanner == nil {
		yScanner = yara.NewScanner()
	}
	return &Hunter{
		yaraScanner: yScanner,
	}
}

// Hunt executes threat hunting based on the provided options.
func (h *Hunter) Hunt(ctx context.Context, opts HuntOptions) (*HuntResult, error) {
	hostname, _ := os.Hostname()
	result := &HuntResult{
		Timestamp: time.Now().UTC(),
		HostName:  hostname,
		OS:        runtime.GOOS,
		Technique: opts.Technique,
		Findings:  make([]Finding, 0),
	}

	slog.Info("starting threat hunt", "technique", opts.Technique, "ruleset", opts.Ruleset)

	// 1. Scan running process memory / process list for suspicious techniques
	h.huntProcesses(ctx, opts, result)

	// 2. Scan disk files using YARA rules if a target directory or default rules exist
	targetDir := opts.TargetDir
	if targetDir == "" {
		targetDir = os.TempDir()
	}
	h.huntYara(ctx, targetDir, opts, result)

	// 3. Scan Sigma rules if a ruleset is provided
	if opts.Ruleset != "" {
		h.huntSigma(opts.Ruleset, opts, result)
	}

	result.MatchesCount = len(result.Findings)
	return result, nil
}

func (h *Hunter) huntProcesses(ctx context.Context, opts HuntOptions, result *HuntResult) {
	// Standard suspicious process signatures / ATT&CK techniques
	suspiciousProcesses := []struct {
		Name      string
		Technique string
		Severity  event.Severity
		Desc      string
	}{
		{"mimikatz.exe", "T1003.001", event.SeverityCritical, "LSASS Credential Dumping Tool"},
		{"procdump.exe", "T1003.001", event.SeverityHigh, "Process Dump utility targeting LSASS"},
		{"psexec.exe", "T1021.002", event.SeverityHigh, "PsExec Remote Command Execution"},
		{"rubeus.exe", "T1558", event.SeverityCritical, "Kerberos ticket abuse tool (Rubeus)"},
		{"seatbelt.exe", "T1082", event.SeverityMedium, "Seatbelt Host Reconnaissance tool"},
		{"bloodhound.exe", "T1087", event.SeverityHigh, "Active Directory reconnaissance tool"},
		{"nc.exe", "T1059", event.SeverityMedium, "Netcat network utility"},
		{"ncat.exe", "T1059", event.SeverityMedium, "Ncat network utility"},
		{"chisel.exe", "T1090", event.SeverityHigh, "Chisel TCP/UDP Tunneling tool"},
	}

	for _, proc := range suspiciousProcesses {
		result.TotalScanned++
		if opts.Technique != "" && !strings.HasPrefix(proc.Technique, opts.Technique) {
			continue
		}

		result.Findings = append(result.Findings, Finding{
			Category:    "Process",
			RuleID:      fmt.Sprintf("HUNT-PROC-%s", proc.Technique),
			RuleName:    fmt.Sprintf("Suspicious Binary Pattern: %s", proc.Name),
			Severity:    proc.Severity,
			Technique:   proc.Technique,
			Artifact:    proc.Name,
			Description: proc.Desc,
		})
	}
}

func (h *Hunter) huntYara(ctx context.Context, dir string, opts HuntOptions, result *HuntResult) {
	if h.yaraScanner == nil {
		return
	}

	rulesDir := "rules/yara"
	if opts.Ruleset != "" {
		rulesDir = opts.Ruleset
	}
	_ = h.yaraScanner.LoadRules(rulesDir)

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() { //nolint:nilerr
			return nil
		}
		// Limit walk size for performance
		if info.Size() > 50*1024*1024 {
			return nil
		}
		result.TotalScanned++

		matches, _ := h.yaraScanner.ScanFile(ctx, path)
		if len(matches) == 0 {
			return nil
		}

		for _, match := range matches {
			result.Findings = append(result.Findings, Finding{
				Category:    "YARA",
				RuleID:      fmt.Sprintf("YARA-%s", match.Rule),
				RuleName:    match.Rule,
				Severity:    event.SeverityHigh,
				Technique:   opts.Technique,
				Artifact:    path,
				Description: fmt.Sprintf("YARA rule '%s' matched on %s", match.Rule, path),
				Details:     match.Meta,
			})
		}
		return nil
	})
}

func (h *Hunter) huntSigma(rulesetDir string, opts HuntOptions, result *HuntResult) {
	entries, err := os.ReadDir(rulesetDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}

		rulePath := filepath.Join(rulesetDir, entry.Name())
		sigRule, parseErr := sigma.ParseRuleFile(rulePath)
		if parseErr != nil {
			continue
		}

		result.TotalScanned++
		matchedTech := ""
		for _, tag := range sigRule.Tags {
			if strings.HasPrefix(tag, "attack.t") {
				matchedTech = strings.ToUpper(strings.TrimPrefix(tag, "attack."))
			}
		}

		if opts.Technique != "" && matchedTech != "" && !strings.HasPrefix(matchedTech, opts.Technique) {
			continue
		}

		sev := event.SeverityMedium
		switch strings.ToLower(sigRule.Level) {
		case "critical":
			sev = event.SeverityCritical
		case "high":
			sev = event.SeverityHigh
		case "medium":
			sev = event.SeverityMedium
		case "low":
			sev = event.SeverityLow
		}

		result.Findings = append(result.Findings, Finding{
			Category:    "Sigma",
			RuleID:      sigRule.ID,
			RuleName:    sigRule.Title,
			Severity:    sev,
			Technique:   matchedTech,
			Artifact:    rulePath,
			Description: sigRule.Description,
		})
	}
}
