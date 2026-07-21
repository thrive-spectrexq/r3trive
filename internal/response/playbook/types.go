package playbook

import (
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/response"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// OnFailureStrategy dictates step failure behavior.
type OnFailureStrategy string

const (
	OnFailureContinue   OnFailureStrategy = "continue"
	OnFailureAlertAdmin OnFailureStrategy = "alert_admin"
	OnFailureAbort      OnFailureStrategy = "abort"
)

// PlaybookTrigger defines conditions that match an incident to a playbook.
type PlaybookTrigger struct {
	IncidentType string         `yaml:"incident_type,omitempty" json:"incident_type,omitempty"`
	RiskScoreGTE int            `yaml:"risk_score_gte,omitempty" json:"risk_score_gte,omitempty"`
	SeverityGTE  event.Severity `yaml:"severity_gte,omitempty" json:"severity_gte,omitempty"`
	Tags         []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// Step represents a single response action within a playbook sequence.
type Step struct {
	Name      string              `yaml:"name" json:"name"`
	Action    response.ActionType `yaml:"action" json:"action"`
	Params    map[string]any      `yaml:"params,omitempty" json:"params,omitempty"`
	OnFailure OnFailureStrategy   `yaml:"on_failure,omitempty" json:"on_failure,omitempty"`
}

// Playbook represents an automated response workflow.
type Playbook struct {
	ID          string          `yaml:"id" json:"id"`
	Name        string          `yaml:"name" json:"name"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Trigger     PlaybookTrigger `yaml:"trigger" json:"trigger"`
	Steps       []Step          `yaml:"steps" json:"steps"`
}

// StepResult captures the outcome of executing a single playbook step.
type StepResult struct {
	StepName  string              `json:"step_name"`
	Action    response.ActionType `json:"action"`
	Success   bool                `json:"success"`
	Message   string              `json:"message"`
	Timestamp time.Time           `json:"timestamp"`
	Error     string              `json:"error,omitempty"`
}

// ExecutionResult captures the overall outcome of running a playbook against an incident.
type ExecutionResult struct {
	PlaybookID   string       `json:"playbook_id"`
	PlaybookName string       `json:"playbook_name"`
	IncidentID   string       `json:"incident_id"`
	StartTime    time.Time    `json:"start_time"`
	EndTime      time.Time    `json:"end_time"`
	Success      bool         `json:"success"`
	StepResults  []StepResult `json:"step_results"`
	RollbackPlan []string     `json:"rollback_plan,omitempty"`
}
