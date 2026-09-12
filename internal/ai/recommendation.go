package ai

import (
	"fmt"
	"strings"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// RecommendedAction describes an AI-recommended containment step with confidence and rollback.
type RecommendedAction struct {
	Action      string  `json:"action"`
	Target      string  `json:"target"`
	Reason      string  `json:"reason"`
	Confidence  float64 `json:"confidence"`
	Rollback    string  `json:"rollback_action"`
	RollbackCmd string  `json:"rollback_command"`
}

// ActionRecommender analyzes incidents and generates scored response actions with rollback guarantees.
type ActionRecommender struct{}

// NewActionRecommender creates a new recommender instance.
func NewActionRecommender() *ActionRecommender {
	return &ActionRecommender{}
}

// RecommendActions suggests ordered containment actions for an incident.
func (r *ActionRecommender) RecommendActions(inc *event.Incident) []RecommendedAction {
	if inc == nil {
		return nil
	}

	var actions []RecommendedAction

	// 1. Process termination for high/critical incidents
	if inc.Severity == event.SeverityCritical || inc.Severity == event.SeverityHigh {
		if len(inc.ArtifactPaths) > 0 {
			primaryProc := inc.ArtifactPaths[0]
			actions = append(actions, RecommendedAction{
				Action:      "kill_process",
				Target:      primaryProc,
				Reason:      fmt.Sprintf("Primary anomalous artifact (%s) associated with %s incident", primaryProc, inc.Severity),
				Confidence:  0.92,
				Rollback:    "log_restart",
				RollbackCmd: fmt.Sprintf("Verify process %s binary integrity before relaunching", primaryProc),
			})
		}
	}

	// 2. Network blocking for C2 / exfiltration
	for _, mapping := range inc.ATTACKMap {
		tech := mapping.Technique
		if strings.HasPrefix(tech, "T1071") || strings.HasPrefix(tech, "T1048") || strings.HasPrefix(tech, "T1041") {
			actions = append(actions, RecommendedAction{
				Action:      "block_ip",
				Target:      "remote_endpoint",
				Reason:      fmt.Sprintf("Outbound connection associated with ATT&CK technique %s", tech),
				Confidence:  0.88,
				Rollback:    "unblock_ip",
				RollbackCmd: "netsh advfirewall firewall delete rule name=\"R3TRIVE_Block_remote_endpoint\"",
			})
			break
		}
	}

	// 3. Host isolation for critical ransomware or widespread lateral movement
	if inc.Severity == event.SeverityCritical && inc.RiskScore >= 90 {
		targetHost := "all_hosts"
		if len(inc.HostIDs) > 0 {
			targetHost = inc.HostIDs[0]
		}
		actions = append(actions, RecommendedAction{
			Action:      "isolate_host",
			Target:      targetHost,
			Reason:      "Risk score >= 90 critical threat detected; host isolation recommended to contain blast radius",
			Confidence:  0.95,
			Rollback:    "unisolate_host",
			RollbackCmd: fmt.Sprintf("r3trive response execute --action unisolate_host --target %s", targetHost),
		})
	}

	return actions
}
