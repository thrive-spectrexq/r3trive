package correlation

import (
	"strings"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// TacticOrder maps standard MITRE ATT&CK tactics to chronological progression index.
var TacticOrder = map[string]int{
	"initial-access":       1,
	"initialaccess":        1,
	"execution":            2,
	"persistence":          3,
	"privilege-escalation": 4,
	"privilegeescalation":  4,
	"defense-evasion":      5,
	"defenseevasion":       5,
	"credential-access":    6,
	"credentialaccess":     6,
	"discovery":            7,
	"lateral-movement":     8,
	"lateralmovement":      8,
	"collection":           9,
	"command-and-control":  10,
	"commandandcontrol":    10,
	"exfiltration":         11,
	"impact":               12,
}

// AttackStage represents an individual progression milestone in an incident.
type AttackStage struct {
	Index       int    `json:"index"`
	Tactic      string `json:"tactic"`
	TechniqueID string `json:"technique_id"`
	RuleName    string `json:"rule_name"`
	RiskScore   int    `json:"risk_score"`
	Timestamp   string `json:"timestamp"`
}

// AttackChainReport contains the chronological progression validation of an incident.
type AttackChainReport struct {
	Stages           []AttackStage `json:"stages"`
	ProgressionScore float64       `json:"progression_score"`
	IsMultiStage     bool          `json:"is_multi_stage"`
	MaxTacticIndex   int           `json:"max_tactic_index"`
}

// ValidateAttackChain analyzes a sequence of correlated alerts and computes a progression score.
func ValidateAttackChain(alerts []event.Alert) AttackChainReport {
	if len(alerts) == 0 {
		return AttackChainReport{}
	}

	stages := make([]AttackStage, 0, len(alerts))
	highestIndex := 0
	monotonicTransitions := 0

	for i, alert := range alerts {
		normTactic := strings.ToLower(strings.ReplaceAll(alert.ATTACKTactic, " ", ""))
		orderIndex := TacticOrder[normTactic]
		if orderIndex == 0 {
			orderIndex = 2 // default to execution if unspecified
		}

		if orderIndex >= highestIndex {
			if highestIndex > 0 && orderIndex > highestIndex {
				monotonicTransitions++
			}
			highestIndex = orderIndex
		}

		stages = append(stages, AttackStage{
			Index:       i + 1,
			Tactic:      alert.ATTACKTactic,
			TechniqueID: alert.ATTACKTechnique,
			RuleName:    alert.RuleName,
			RiskScore:   alert.RiskScore,
			Timestamp:   alert.Timestamp.Format("15:04:05"),
		})
	}

	isMultiStage := highestIndex > 3 && len(stages) >= 2

	// Score is proportional to stages observed and monotonic progression
	progressionScore := float64(highestIndex)*7.0 + float64(monotonicTransitions)*10.0
	if progressionScore > 100.0 {
		progressionScore = 100.0
	}

	return AttackChainReport{
		Stages:           stages,
		ProgressionScore: progressionScore,
		IsMultiStage:     isMultiStage,
		MaxTacticIndex:   highestIndex,
	}
}
