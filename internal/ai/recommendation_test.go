package ai

import (
	"testing"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestActionRecommender(t *testing.T) {
	rec := NewActionRecommender()

	// Nil incident returns nil
	if actions := rec.RecommendActions(nil); actions != nil {
		t.Fatalf("expected nil actions for nil incident")
	}

	inc := &event.Incident{
		ID:            "INC-001",
		Severity:      event.SeverityCritical,
		RiskScore:     95,
		ArtifactPaths: []string{"mimikatz.exe"},
		HostIDs:       []string{"finance-srv"},
		ATTACKMap: []event.ATTACKMapping{
			{Tactic: "Credential Access", Technique: "T1003.001"},
			{Tactic: "Command and Control", Technique: "T1071.001"},
		},
	}

	actions := rec.RecommendActions(inc)
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 recommended actions, got: %d", len(actions))
	}

	// Verify kill_process
	if actions[0].Action != "kill_process" || actions[0].Target != "mimikatz.exe" {
		t.Fatalf("expected kill_process action, got: %+v", actions[0])
	}
	if actions[0].Confidence < 0.90 {
		t.Fatalf("expected high confidence, got: %f", actions[0].Confidence)
	}

	// Verify isolate_host
	hasIsolation := false
	for _, act := range actions {
		if act.Action == "isolate_host" && act.Rollback == "unisolate_host" {
			hasIsolation = true
			break
		}
	}
	if !hasIsolation {
		t.Fatalf("expected host isolation recommendation for critical 95 risk score incident")
	}
}
