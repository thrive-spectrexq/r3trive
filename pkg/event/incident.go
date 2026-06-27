package event

import "time"

// IncidentStatus represents the lifecycle state of an incident.
type IncidentStatus string

// Incident lifecycle states.
const (
	IncidentStatusOpen          IncidentStatus = "open"
	IncidentStatusInvestigating IncidentStatus = "investigating"
	IncidentStatusContained     IncidentStatus = "contained"
	IncidentStatusResolved      IncidentStatus = "resolved"
	IncidentStatusFalsePositive IncidentStatus = "false_positive"
)

// ATTACKMapping represents a MITRE ATT&CK technique mapping.
type ATTACKMapping struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	SubID     string `json:"sub_id,omitempty"`
	Name      string `json:"name,omitempty"`
}

// Incident is a correlated group of alerts representing a threat campaign.
type Incident struct {
	ID          string         `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Status      IncidentStatus `json:"status"`
	Severity    Severity       `json:"severity"`
	RiskScore   int            `json:"risk_score"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`

	// Related data
	Alerts        []Alert         `json:"alerts"`
	HostIDs       []string        `json:"host_ids"`
	ATTACKMap     []ATTACKMapping `json:"attack_map,omitempty"`
	ArtifactPaths []string        `json:"artifact_paths,omitempty"`

	// Response tracking
	ResponseActions []string `json:"response_actions,omitempty"`
	AssignedTo      string   `json:"assigned_to,omitempty"`
	Notes           string   `json:"notes,omitempty"`
}
