package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// AggregatorConfig holds configuration for the incident aggregator.
type AggregatorConfig struct {
	// CorrelateWindow defines how long related alerts are grouped into an existing open incident.
	CorrelateWindow time.Duration
	// MinIncidentRiskScore is the minimum score required to create/escalate an incident.
	MinIncidentRiskScore int
}

// DefaultAggregatorConfig returns the default configuration for incident aggregation.
func DefaultAggregatorConfig() AggregatorConfig {
	return AggregatorConfig{
		CorrelateWindow:      15 * time.Minute,
		MinIncidentRiskScore: 20,
	}
}

// IncidentAggregator correlates incoming alerts into coherent security incidents
// and persists both alerts and incidents to the storage backend.
type IncidentAggregator struct {
	store           storage.Store
	cfg             AggregatorConfig
	mu              sync.Mutex
	activeIncidents map[string]*event.Incident // key: host identifier
}

// NewIncidentAggregator creates a new incident aggregator.
func NewIncidentAggregator(store storage.Store, cfg AggregatorConfig) *IncidentAggregator {
	if cfg.CorrelateWindow <= 0 {
		cfg.CorrelateWindow = 15 * time.Minute
	}
	return &IncidentAggregator{
		store:           store,
		cfg:             cfg,
		activeIncidents: make(map[string]*event.Incident),
	}
}

// ProcessAlert aggregates an alert into an incident, calculates composite risk,
// and saves both the alert and incident in the persistent store.
func (a *IncidentAggregator) ProcessAlert(ctx context.Context, alert event.Alert) (*event.Incident, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	hostKey := alert.Event.Host.ID
	if hostKey == "" {
		hostKey = alert.Event.Host.Hostname
	}
	if hostKey == "" {
		hostKey = "unknown-host"
	}

	now := alert.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
		alert.Timestamp = now
	}

	inc, exists := a.activeIncidents[hostKey]
	withinWindow := exists && now.Sub(inc.UpdatedAt) <= a.cfg.CorrelateWindow && inc.Status == event.IncidentStatusOpen

	if withinWindow {
		// Append alert to existing incident
		alert.IncidentID = inc.ID
		inc.Alerts = append(inc.Alerts, alert)
		inc.UpdatedAt = now

		// Escalate severity if the new alert is more severe
		if alert.Severity.Weight() > inc.Severity.Weight() {
			inc.Severity = alert.Severity
		}

		// Recalculate composite incident risk score
		inc.RiskScore = CalculateIncidentScore(inc.Alerts)

		// Merge ATT&CK techniques
		if alert.ATTACKTactic != "" || alert.ATTACKTechnique != "" {
			addAttackMapping(inc, alert.ATTACKTactic, alert.ATTACKTechnique)
		}

		// Merge artifact paths
		extractArtifacts(inc, alert.Event)

		slog.Info("correlated alert into existing incident",
			"incident_id", inc.ID,
			"alert_id", alert.ID,
			"rule_name", alert.RuleName,
			"risk_score", inc.RiskScore,
			"severity", inc.Severity,
		)
	} else {
		// Create new security incident
		incID := fmt.Sprintf("INC-%s", uuid.New().String()[:8])
		alert.IncidentID = incID

		title := fmt.Sprintf("%s on %s", alert.RuleName, hostKey)
		if alert.RuleName == "" {
			title = fmt.Sprintf("Security Alert on %s", hostKey)
		}

		inc = &event.Incident{
			ID:              incID,
			CreatedAt:       now,
			UpdatedAt:       now,
			Status:          event.IncidentStatusOpen,
			Severity:        alert.Severity,
			RiskScore:       alert.RiskScore,
			Title:           title,
			Description:     alert.Message,
			Alerts:          []event.Alert{alert},
			HostIDs:         []string{hostKey},
			ResponseActions: make([]string, 0),
		}

		if alert.ATTACKTactic != "" || alert.ATTACKTechnique != "" {
			addAttackMapping(inc, alert.ATTACKTactic, alert.ATTACKTechnique)
		}

		extractArtifacts(inc, alert.Event)

		a.activeIncidents[hostKey] = inc

		slog.Info("created new incident from alert",
			"incident_id", inc.ID,
			"alert_id", alert.ID,
			"rule_name", alert.RuleName,
			"risk_score", inc.RiskScore,
			"severity", inc.Severity,
		)
	}

	// Persist event, alert, and incident if store is available
	if a.store != nil {
		if alert.Event.ID == "" {
			alert.Event.ID = fmt.Sprintf("evt_%s", uuid.New().String()[:8])
		}
		if alert.Event.Timestamp.IsZero() {
			alert.Event.Timestamp = now
		}

		if err := a.store.SaveEvent(ctx, alert.Event); err != nil {
			slog.Error("failed to persist triggering event", "event_id", alert.Event.ID, "error", err)
			return inc, fmt.Errorf("persisting event %s: %w", alert.Event.ID, err)
		}

		if err := a.store.SaveAlert(ctx, alert); err != nil {
			slog.Error("failed to persist alert", "alert_id", alert.ID, "error", err)
			return inc, fmt.Errorf("persisting alert %s: %w", alert.ID, err)
		}

		if err := a.store.SaveIncident(ctx, *inc); err != nil {
			slog.Error("failed to persist incident", "incident_id", inc.ID, "error", err)
			return inc, fmt.Errorf("persisting incident %s: %w", inc.ID, err)
		}
	}

	return inc, nil
}

// GetActiveIncident returns the currently active incident for a host, if any.
func (a *IncidentAggregator) GetActiveIncident(hostKey string) (*event.Incident, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	inc, exists := a.activeIncidents[hostKey]
	if !exists {
		return nil, false
	}
	return inc, true
}

func addAttackMapping(inc *event.Incident, tactic, technique string) {
	for _, m := range inc.ATTACKMap {
		if m.Tactic == tactic && m.Technique == technique {
			return
		}
	}
	inc.ATTACKMap = append(inc.ATTACKMap, event.ATTACKMapping{
		Tactic:    tactic,
		Technique: technique,
	})
}

func extractArtifacts(inc *event.Incident, evt event.Event) {
	var paths []string

	if evt.Data.Process != nil {
		if evt.Data.Process.Path != "" {
			paths = append(paths, evt.Data.Process.Path)
		}
	}

	if evt.Data.File != nil {
		if evt.Data.File.Path != "" {
			paths = append(paths, evt.Data.File.Path)
		}
	}

	for _, p := range paths {
		duplicate := false
		for _, existing := range inc.ArtifactPaths {
			if existing == p {
				duplicate = true
				break
			}
		}
		if !duplicate {
			inc.ArtifactPaths = append(inc.ArtifactPaths, p)
		}
	}
}
