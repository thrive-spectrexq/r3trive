package investigator

import (
	"context"
	"crypto/md5" // #nosec G501
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// InvestigationReport represents the complete output of an investigation.
type InvestigationReport struct {
	Target            string                `json:"target"`
	TargetType        string                `json:"target_type"` // binary, process, incident
	Timestamp         time.Time             `json:"timestamp"`
	RiskScore         int                   `json:"risk_score"`
	Severity          event.Severity        `json:"severity"`
	FileHashes        map[string]string     `json:"file_hashes,omitempty"`
	Entropy           float64               `json:"entropy,omitempty"`
	Findings          []Finding             `json:"findings"`
	ATTACKTechniques  []event.ATTACKMapping `json:"attack_techniques"`
	RecommendedAction string                `json:"recommended_action"`
}

// Finding represents a single finding within an investigation.
type Finding struct {
	Severity event.Severity `json:"severity"`
	Message  string         `json:"message"`
	Details  string         `json:"details,omitempty"`
}

// Investigator performs deep diagnostic analysis on files, processes, and incidents.
type Investigator struct {
	yaraScanner yara.Scanner
	store       storage.Store
}

// New creates a new Investigator instance.
func New(yScanner yara.Scanner, store storage.Store) *Investigator {
	if yScanner == nil {
		yScanner = yara.NewScanner()
	}
	return &Investigator{
		yaraScanner: yScanner,
		store:       store,
	}
}

// InvestigateBinary analyzes a binary or executable file.
func (inv *Investigator) InvestigateBinary(ctx context.Context, filePath string) (*InvestigationReport, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat target file: %w", err)
	}

	content, err := os.ReadFile(filePath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("read target file: %w", err)
	}

	// 1. Calculate Hashes
	sha256Hash := sha256.Sum256(content)
	md5Hash := md5.Sum(content) // #nosec G401
	hashes := map[string]string{
		"sha256": hex.EncodeToString(sha256Hash[:]),
		"md5":    hex.EncodeToString(md5Hash[:]),
	}

	// 2. Compute Entropy
	entropy := calculateEntropy(content)

	report := &InvestigationReport{
		Target:           filePath,
		TargetType:       "binary",
		Timestamp:        time.Now().UTC(),
		FileHashes:       hashes,
		Entropy:          entropy,
		Findings:         make([]Finding, 0),
		ATTACKTechniques: make([]event.ATTACKMapping, 0),
	}

	riskPoints := 0

	// Entropy check
	if entropy > 7.5 {
		riskPoints += 25
		report.Findings = append(report.Findings, Finding{
			Severity: event.SeverityMedium,
			Message:  fmt.Sprintf("Packed/obfuscated binary (entropy %.2f)", entropy),
		})
	}

	// YARA Scan
	yaraMatches, yErr := inv.yaraScanner.ScanFile(ctx, filePath)
	if yErr == nil && len(yaraMatches) > 0 {
		for _, m := range yaraMatches {
			riskPoints += 40
			report.Findings = append(report.Findings, Finding{
				Severity: event.SeverityHigh,
				Message:  fmt.Sprintf("YARA match: %s (Namespace: %s)", m.Rule, m.Namespace),
			})
		}
	}

	// Heuristic inspection on binary strings
	strContent := string(content)
	lowerContent := strings.ToLower(strContent)

	if strings.Contains(lowerContent, "185.220.101.47") || strings.Contains(lowerContent, ".onion") || strings.Contains(lowerContent, "tor") {
		riskPoints += 40
		report.Findings = append(report.Findings, Finding{
			Severity: event.SeverityCritical,
			Message:  "Network beaconing indicator detected (Tor exit node / C2 domain)",
		})
		report.ATTACKTechniques = append(report.ATTACKTechniques, event.ATTACKMapping{
			Tactic: "Command and Control", Technique: "T1071.001", Name: "Application Layer Protocol: Web Protocols",
		})
	}

	if strings.Contains(lowerContent, "hkcu\\software\\microsoft\\windows\\currentversion\\run") || strings.Contains(lowerContent, "hkcu\\run") {
		riskPoints += 30
		report.Findings = append(report.Findings, Finding{
			Severity: event.SeverityHigh,
			Message:  "Registry persistence key reference (HKCU\\Run)",
		})
		report.ATTACKTechniques = append(report.ATTACKTechniques, event.ATTACKMapping{
			Tactic: "Persistence", Technique: "T1547.001", Name: "Boot or Logon Autostart: Registry Run Keys",
		})
	}

	if strings.Contains(lowerContent, "sedebugprivilege") || strings.Contains(lowerContent, "lsass") {
		riskPoints += 35
		report.Findings = append(report.Findings, Finding{
			Severity: event.SeverityHigh,
			Message:  "Privilege escalation / Credential access attempt (SeDebugPrivilege / LSASS)",
		})
		report.ATTACKTechniques = append(report.ATTACKTechniques, event.ATTACKMapping{
			Tactic: "Credential Access", Technique: "T1003.001", Name: "OS Credential Dumping: LSASS Memory",
		})
	}

	if strings.Contains(lowerContent, "createremotethread") || strings.Contains(lowerContent, "virtualalloc-ex") {
		riskPoints += 30
		report.Findings = append(report.Findings, Finding{
			Severity: event.SeverityHigh,
			Message:  "Process injection APIs present (CreateRemoteThread/VirtualAllocEx)",
		})
		report.ATTACKTechniques = append(report.ATTACKTechniques, event.ATTACKMapping{
			Tactic: "Defense Evasion", Technique: "T1055", Name: "Process Injection",
		})
	}

	// Cap risk score at 100
	if riskPoints > 100 {
		riskPoints = 100
	}
	report.RiskScore = riskPoints
	report.Severity = riskScoreToSeverity(riskPoints)
	report.RecommendedAction = deriveRecommendedAction(riskPoints)

	_ = fileInfo
	return report, nil
}

// InvestigateProcess inspects a running process by PID.
func (inv *Investigator) InvestigateProcess(ctx context.Context, pid int) (*InvestigationReport, error) {
	report := &InvestigationReport{
		Target:           fmt.Sprintf("PID:%d", pid),
		TargetType:       "process",
		Timestamp:        time.Now().UTC(),
		Findings:         make([]Finding, 0),
		ATTACKTechniques: make([]event.ATTACKMapping, 0),
	}

	riskPoints := 50 // Base investigation baseline for running process audit

	// Scan process memory with YARA
	matches, err := inv.yaraScanner.ScanProcessMemory(ctx, pid)
	if err == nil && len(matches) > 0 {
		for _, m := range matches {
			riskPoints += 35
			report.Findings = append(report.Findings, Finding{
				Severity: event.SeverityCritical,
				Message:  fmt.Sprintf("Memory YARA match: %s", m.Rule),
			})
		}
	}

	report.Findings = append(report.Findings, Finding{
		Severity: event.SeverityMedium,
		Message:  fmt.Sprintf("Process PID %d inspected", pid),
	})

	if riskPoints > 100 {
		riskPoints = 100
	}
	report.RiskScore = riskPoints
	report.Severity = riskScoreToSeverity(riskPoints)
	report.RecommendedAction = deriveRecommendedAction(riskPoints)

	return report, nil
}

// InvestigateIncident performs analysis on a stored incident.
func (inv *Investigator) InvestigateIncident(ctx context.Context, incidentID string) (*InvestigationReport, error) {
	report := &InvestigationReport{
		Target:           incidentID,
		TargetType:       "incident",
		Timestamp:        time.Now().UTC(),
		Findings:         make([]Finding, 0),
		ATTACKTechniques: make([]event.ATTACKMapping, 0),
	}

	if inv.store == nil {
		return nil, fmt.Errorf("storage driver not configured")
	}

	inc, err := inv.store.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, fmt.Errorf("fetching incident %s: %w", incidentID, err)
	}

	report.RiskScore = inc.RiskScore
	report.Severity = inc.Severity
	report.ATTACKTechniques = inc.ATTACKMap

	for _, alert := range inc.Alerts {
		report.Findings = append(report.Findings, Finding{
			Severity: alert.Severity,
			Message:  fmt.Sprintf("[%s] %s (Rule: %s)", alert.Severity, alert.Message, alert.RuleName),
		})
	}

	report.RecommendedAction = deriveRecommendedAction(inc.RiskScore)
	return report, nil
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	total := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func riskScoreToSeverity(score int) event.Severity {
	switch {
	case score >= 80:
		return event.SeverityCritical
	case score >= 60:
		return event.SeverityHigh
	case score >= 35:
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

func deriveRecommendedAction(score int) string {
	switch {
	case score >= 80:
		return "IMMEDIATE ISOLATION & PROCESS TERMINATION"
	case score >= 60:
		return "QUARANTINE BINARY AND MONITOR SUSPICIOUS PID"
	case score >= 35:
		return "EVALUATE HOST SECURITY BASELINE & ENRICH LOGS"
	default:
		return "NO IMMEDIATE ACTION REQUIRED (MONITOR)"
	}
}
