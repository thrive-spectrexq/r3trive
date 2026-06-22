package event

import "time"

// Alert represents a flagged event that matched a detection rule.
type Alert struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Event      Event     `json:"event"`
	RuleID     string    `json:"rule_id"`
	RuleName   string    `json:"rule_name"`
	Severity   Severity  `json:"severity"`
	Confidence float64   `json:"confidence"` // 0.0 – 1.0
	RiskScore  int       `json:"risk_score"` // 0 – 100
	Message    string    `json:"message"`

	// ATT&CK mapping
	ATTACKTactic    string `json:"attack_tactic,omitempty"`
	ATTACKTechnique string `json:"attack_technique,omitempty"`

	// Response
	Acknowledged bool   `json:"acknowledged"`
	IncidentID   string `json:"incident_id,omitempty"`
}
