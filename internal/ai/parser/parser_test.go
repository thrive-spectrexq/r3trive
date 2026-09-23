package parser

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	input := `Here is the analysis:
{
	"executive_summary": "Suspicious execution of powershell",
	"confidence_score": 0.85
}
Hope this helps!`

	var target struct {
		Summary    string  `json:"executive_summary"`
		Confidence float64 `json:"confidence_score"`
	}

	err := ExtractJSON(input, &target)
	if err != nil {
		t.Fatalf("ExtractJSON failed: %v", err)
	}
	if target.Summary != "Suspicious execution of powershell" {
		t.Errorf("unexpected summary: %s", target.Summary)
	}
	if target.Confidence != 0.85 {
		t.Errorf("unexpected confidence: %f", target.Confidence)
	}
}

func TestExtractYAMLBlock(t *testing.T) {
	input := "```yaml\nid: R3-001\nname: Test Rule\ntype: atomic\nseverity: high\nconfidence: 0.9\nconditions:\n  - field: process.name\n    operator: eq\n    value: cmd.exe\n```"
	extracted := ExtractYAMLBlock(input)
	if extracted == "" || extracted == input {
		t.Errorf("failed to extract YAML block")
	}

	parsed, err := ParseRuleResponse(input)
	if err != nil {
		t.Fatalf("ParseRuleResponse failed: %v", err)
	}
	if parsed.ID != "R3-001" {
		t.Errorf("expected ID R3-001, got %s", parsed.ID)
	}
}

func TestExtractConfidenceScore(t *testing.T) {
	score1 := ExtractConfidenceScore("Overall confidence: 88%")
	if score1 != 0.88 {
		t.Errorf("expected 0.88, got %f", score1)
	}

	score2 := ExtractConfidenceScore("This has High Confidence")
	if score2 != 0.90 {
		t.Errorf("expected 0.90, got %f", score2)
	}
}

func TestParseActionRecommendations(t *testing.T) {
	// 1. Valid JSON recommendations
	jsonInput := `Here are the proposed defensive responses:
[
	{
		"action": "kill_process",
		"target": "4567",
		"reason": "Malicious credential dumping",
		"risk": "medium"
	},
	{
		"action": "block_ip",
		"target": "198.51.100.42",
		"reason": "C2 communication",
		"risk": "low"
	}
]`
	actions, err := ParseActionRecommendations(jsonInput)
	if err != nil {
		t.Fatalf("expected successful parsing of JSON recommendations, got: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
	if actions[0].Action != "kill_process" || actions[0].Target != "4567" {
		t.Errorf("unexpected action 0: %+v", actions[0])
	}

	// 2. Reject malicious PID 1 in kill_process
	badPIDInput := `[{"action":"kill_process","target":"1"}]`
	if _, err := ParseActionRecommendations(badPIDInput); err == nil {
		t.Error("expected error when attempting to kill PID 1")
	}

	// 3. Reject loopback IP in block_ip
	badIPInput := `[{"action":"block_ip","target":"127.0.0.1"}]`
	if _, err := ParseActionRecommendations(badIPInput); err == nil {
		t.Error("expected error when attempting to block loopback IP")
	}

	// 4. Reject critical system paths in quarantine
	badPathInput := `[{"action":"quarantine_file","target":"C:\\Windows"}]`
	if _, err := ParseActionRecommendations(badPathInput); err == nil {
		t.Error("expected error when attempting to quarantine C:\\Windows")
	}
}
