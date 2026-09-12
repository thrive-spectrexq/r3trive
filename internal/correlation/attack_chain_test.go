package correlation

import (
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestValidateAttackChain(t *testing.T) {
	// Empty alerts
	emptyReport := ValidateAttackChain(nil)
	if len(emptyReport.Stages) != 0 || emptyReport.ProgressionScore != 0 {
		t.Fatalf("expected empty report for nil alerts")
	}

	// Sequential multi-stage attack: Execution -> Persistence -> Lateral Movement -> Exfiltration
	now := time.Now()
	alerts := []event.Alert{
		{
			RuleName:        "Suspicious PowerShell",
			ATTACKTactic:    "Execution",
			ATTACKTechnique: "T1059.001",
			RiskScore:       60,
			Timestamp:       now,
		},
		{
			RuleName:        "Registry Run Key",
			ATTACKTactic:    "Persistence",
			ATTACKTechnique: "T1547.001",
			RiskScore:       70,
			Timestamp:       now.Add(1 * time.Minute),
		},
		{
			RuleName:        "WMI Remote Process",
			ATTACKTactic:    "Lateral Movement",
			ATTACKTechnique: "T1047",
			RiskScore:       85,
			Timestamp:       now.Add(2 * time.Minute),
		},
		{
			RuleName:        "DNS Exfiltration",
			ATTACKTactic:    "Exfiltration",
			ATTACKTechnique: "T1048",
			RiskScore:       95,
			Timestamp:       now.Add(3 * time.Minute),
		},
	}

	report := ValidateAttackChain(alerts)
	if !report.IsMultiStage {
		t.Fatalf("expected report to be flagged as multi-stage attack")
	}
	if len(report.Stages) != 4 {
		t.Fatalf("expected 4 stages, got %d", len(report.Stages))
	}
	if report.MaxTacticIndex != 11 { // Exfiltration is index 11
		t.Fatalf("expected max tactic index 11, got %d", report.MaxTacticIndex)
	}
	if report.ProgressionScore < 70.0 {
		t.Fatalf("expected high progression score for full kill-chain, got %f", report.ProgressionScore)
	}
}
