// Package sqlite implements the storage.Store interface using SQLite.
// It uses WAL mode for concurrent reads and batches writes for performance.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

//go:embed migrations/001_initial.sql
var migrationSQL string

// Store implements storage.Store using SQLite.
type Store struct {
	db *sql.DB
}

// New creates a new SQLite store at the given path.
// The database file and parent directories are created if they don't exist.
func New(dsn string) (*Store, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(dsn)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("sqlite: creating directory %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: opening %s: %w", dsn, err)
	}

	// Enable WAL mode for concurrent reads
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: enabling WAL: %w", err)
	}

	// Performance pragmas
	pragmas := []string{
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-64000", // 64MB cache
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			slog.Warn("sqlite pragma failed", "pragma", p, "error", err)
		}
	}

	// Run migrations
	if _, err := db.Exec(migrationSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: running migrations: %w", err)
	}

	slog.Info("sqlite store initialized", "path", dsn)

	return &Store{db: db}, nil
}

// SaveEvent persists a single event.
func (s *Store) SaveEvent(ctx context.Context, evt event.Event) error {
	return s.SaveEvents(ctx, []event.Event{evt})
}

// SaveEvents persists a batch of events in a single transaction.
func (s *Store) SaveEvents(ctx context.Context, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO events (id, timestamp, host_id, hostname, type, severity, sensor, data, enrichments, chain_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, evt := range events {
		dataJSON, err := json.Marshal(evt.Data)
		if err != nil {
			slog.Error("sqlite: marshaling event data", "event_id", evt.ID, "error", err)
			continue
		}

		var enrichJSON []byte
		if len(evt.Enrichments) > 0 {
			enrichJSON, _ = json.Marshal(evt.Enrichments)
		}

		_, err = stmt.ExecContext(ctx,
			evt.ID,
			evt.Timestamp,
			evt.Host.ID,
			evt.Host.Hostname,
			string(evt.Type),
			string(evt.Severity),
			evt.Sensor,
			string(dataJSON),
			string(enrichJSON),
			evt.ChainHash,
		)
		if err != nil {
			slog.Error("sqlite: inserting event", "event_id", evt.ID, "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}

	return nil
}

// QueryEvents retrieves events matching the query filters.
func (s *Store) QueryEvents(ctx context.Context, q storage.EventQuery) ([]event.Event, error) {
	query := "SELECT id, timestamp, host_id, hostname, type, severity, sensor, data, enrichments, chain_hash FROM events WHERE 1=1"
	args := []any{}

	if q.Type != "" {
		query += " AND type = ?"
		args = append(args, q.Type)
	}
	if q.Severity != "" {
		query += " AND severity = ?"
		args = append(args, q.Severity)
	}
	if q.HostID != "" {
		query += " AND host_id = ?"
		args = append(args, q.HostID)
	}
	if !q.Since.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, q.Since)
	}
	if !q.Until.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, q.Until)
	}

	query += " ORDER BY timestamp DESC"

	if q.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, q.Limit)
	}
	if q.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, q.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query events: %w", err)
	}
	defer rows.Close()

	var events []event.Event
	for rows.Next() {
		var (
			evt        event.Event
			dataJSON   string
			enrichJSON sql.NullString
			chainHash  sql.NullString
		)

		err := rows.Scan(
			&evt.ID,
			&evt.Timestamp,
			&evt.Host.ID,
			&evt.Host.Hostname,
			&evt.Type,
			&evt.Severity,
			&evt.Sensor,
			&dataJSON,
			&enrichJSON,
			&chainHash,
		)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scanning row: %w", err)
		}

		if err := json.Unmarshal([]byte(dataJSON), &evt.Data); err != nil {
			slog.Warn("sqlite: unmarshaling event data", "event_id", evt.ID, "error", err)
		}
		if enrichJSON.Valid {
			_ = json.Unmarshal([]byte(enrichJSON.String), &evt.Enrichments) // #nosec G104
		}
		if chainHash.Valid {
			evt.ChainHash = chainHash.String
		}

		events = append(events, evt)
	}

	return events, rows.Err()
}

// SaveAlert persists an alert record.
func (s *Store) SaveAlert(ctx context.Context, alert event.Alert) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO alerts (id, timestamp, event_id, rule_id, rule_name, severity, confidence, risk_score, message, attack_tactic, attack_technique, acknowledged, incident_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		alert.ID,
		alert.Timestamp,
		alert.Event.ID,
		alert.RuleID,
		alert.RuleName,
		string(alert.Severity),
		alert.Confidence,
		alert.RiskScore,
		alert.Message,
		alert.ATTACKTactic,
		alert.ATTACKTechnique,
		alert.Acknowledged,
		alert.IncidentID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: saving alert: %w", err)
	}
	return nil
}

// SaveIncident persists an incident record.
func (s *Store) SaveIncident(ctx context.Context, incident event.Incident) error {
	hostIDsJSON, _ := json.Marshal(incident.HostIDs)
	attackMapJSON, _ := json.Marshal(incident.ATTACKMap)
	artifactJSON, _ := json.Marshal(incident.ArtifactPaths)
	actionsJSON, _ := json.Marshal(incident.ResponseActions)

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO incidents (id, created_at, updated_at, status, severity, risk_score, title, description, host_ids, attack_map, artifact_paths, response_actions, assigned_to, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		incident.ID,
		incident.CreatedAt,
		incident.UpdatedAt,
		string(incident.Status),
		string(incident.Severity),
		incident.RiskScore,
		incident.Title,
		incident.Description,
		string(hostIDsJSON),
		string(attackMapJSON),
		string(artifactJSON),
		string(actionsJSON),
		incident.AssignedTo,
		incident.Notes,
	)
	if err != nil {
		return fmt.Errorf("sqlite: saving incident: %w", err)
	}
	return nil
}

// GetEvent retrieves a specific event by ID.
func (s *Store) GetEvent(ctx context.Context, id string) (event.Event, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, timestamp, host_id, hostname, type, severity, sensor, data, enrichments, chain_hash 
		 FROM events WHERE id = ?`, id)

	var (
		evt        event.Event
		dataJSON   string
		enrichJSON sql.NullString
		chainHash  sql.NullString
	)

	err := row.Scan(
		&evt.ID,
		&evt.Timestamp,
		&evt.Host.ID,
		&evt.Host.Hostname,
		&evt.Type,
		&evt.Severity,
		&evt.Sensor,
		&dataJSON,
		&enrichJSON,
		&chainHash,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return event.Event{}, fmt.Errorf("event not found: %s", id)
		}
		return event.Event{}, fmt.Errorf("sqlite: scanning event: %w", err)
	}

	if err := json.Unmarshal([]byte(dataJSON), &evt.Data); err != nil {
		slog.Warn("sqlite: unmarshaling event data", "event_id", evt.ID, "error", err)
	}
	if enrichJSON.Valid {
		_ = json.Unmarshal([]byte(enrichJSON.String), &evt.Enrichments) // #nosec G104
	}
	if chainHash.Valid {
		evt.ChainHash = chainHash.String
	}

	return evt, nil
}

// GetIncident retrieves a specific incident by ID, including its associated alerts.
func (s *Store) GetIncident(ctx context.Context, id string) (event.Incident, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, created_at, updated_at, status, severity, risk_score, title, description, host_ids, attack_map, artifact_paths, response_actions, assigned_to, notes 
		 FROM incidents WHERE id = ?`, id)

	var inc event.Incident
	var (
		hostIDsJSON, attackMapJSON, artifactJSON, actionsJSON string
		description, assignedTo, notes                        sql.NullString
	)

	err := row.Scan(
		&inc.ID, &inc.CreatedAt, &inc.UpdatedAt, &inc.Status, &inc.Severity, &inc.RiskScore, &inc.Title,
		&description, &hostIDsJSON, &attackMapJSON, &artifactJSON, &actionsJSON, &assignedTo, &notes,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return event.Incident{}, fmt.Errorf("incident not found: %s", id)
		}
		return event.Incident{}, fmt.Errorf("sqlite: scanning incident: %w", err)
	}

	if description.Valid {
		inc.Description = description.String
	}
	if assignedTo.Valid {
		inc.AssignedTo = assignedTo.String
	}
	if notes.Valid {
		inc.Notes = notes.String
	}

	_ = json.Unmarshal([]byte(hostIDsJSON), &inc.HostIDs)         // #nosec G104
	_ = json.Unmarshal([]byte(attackMapJSON), &inc.ATTACKMap)     // #nosec G104
	_ = json.Unmarshal([]byte(artifactJSON), &inc.ArtifactPaths)  // #nosec G104
	_ = json.Unmarshal([]byte(actionsJSON), &inc.ResponseActions) // #nosec G104

	// Load alerts
	alertRows, err := s.db.QueryContext(ctx, `SELECT id, timestamp, event_id, rule_id, rule_name, severity, confidence, risk_score, message, attack_tactic, attack_technique, acknowledged FROM alerts WHERE incident_id = ?`, inc.ID)
	if err == nil {
		for alertRows.Next() {
			var alert event.Alert
			alert.IncidentID = inc.ID
			var (
				tactic, technique sql.NullString
			)
			err := alertRows.Scan(&alert.ID, &alert.Timestamp, &alert.Event.ID, &alert.RuleID, &alert.RuleName, &alert.Severity, &alert.Confidence, &alert.RiskScore, &alert.Message, &tactic, &technique, &alert.Acknowledged)
			if err == nil {
				if tactic.Valid {
					alert.ATTACKTactic = tactic.String
				}
				if technique.Valid {
					alert.ATTACKTechnique = technique.String
				}
				inc.Alerts = append(inc.Alerts, alert)
			}
		}
		_ = alertRows.Close() // #nosec G104
	}

	return inc, nil
}

// QueryIncidents retrieves incidents matching the given statuses.
func (s *Store) QueryIncidents(ctx context.Context, statuses []event.IncidentStatus) ([]event.Incident, error) {
	if len(statuses) == 0 {
		return nil, nil
	}

	query := `SELECT id, created_at, updated_at, status, severity, risk_score, title, description, host_ids, attack_map, artifact_paths, response_actions, assigned_to, notes FROM incidents WHERE status IN (`
	args := make([]any, len(statuses))
	for i, status := range statuses {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args[i] = string(status)
	}
	query += `) ORDER BY created_at ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query incidents: %w", err)
	}
	defer rows.Close()

	var incidents []event.Incident
	for rows.Next() {
		var inc event.Incident
		var (
			hostIDsJSON, attackMapJSON, artifactJSON, actionsJSON string
			description, assignedTo, notes                        sql.NullString
		)

		err := rows.Scan(
			&inc.ID, &inc.CreatedAt, &inc.UpdatedAt, &inc.Status, &inc.Severity, &inc.RiskScore, &inc.Title,
			&description, &hostIDsJSON, &attackMapJSON, &artifactJSON, &actionsJSON, &assignedTo, &notes,
		)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scanning incident: %w", err)
		}

		if description.Valid {
			inc.Description = description.String
		}
		if assignedTo.Valid {
			inc.AssignedTo = assignedTo.String
		}
		if notes.Valid {
			inc.Notes = notes.String
		}

		_ = json.Unmarshal([]byte(hostIDsJSON), &inc.HostIDs)         // #nosec G104
		_ = json.Unmarshal([]byte(attackMapJSON), &inc.ATTACKMap)     // #nosec G104
		_ = json.Unmarshal([]byte(artifactJSON), &inc.ArtifactPaths)  // #nosec G104
		_ = json.Unmarshal([]byte(actionsJSON), &inc.ResponseActions) // #nosec G104

		// Need to load alerts separately for the incident
		alertRows, err := s.db.QueryContext(ctx, `SELECT id, timestamp, event_id, rule_id, rule_name, severity, confidence, risk_score, message, attack_tactic, attack_technique, acknowledged FROM alerts WHERE incident_id = ?`, inc.ID)
		if err == nil {
			for alertRows.Next() {
				var alert event.Alert
				alert.IncidentID = inc.ID
				var (
					tactic, technique sql.NullString
				)
				err := alertRows.Scan(&alert.ID, &alert.Timestamp, &alert.Event.ID, &alert.RuleID, &alert.RuleName, &alert.Severity, &alert.Confidence, &alert.RiskScore, &alert.Message, &tactic, &technique, &alert.Acknowledged)
				if err == nil {
					if tactic.Valid {
						alert.ATTACKTactic = tactic.String
					}
					if technique.Valid {
						alert.ATTACKTechnique = technique.String
					}
					inc.Alerts = append(inc.Alerts, alert)
				}
			}
			_ = alertRows.Close() // #nosec G104
		}

		incidents = append(incidents, inc)
	}

	return incidents, rows.Err()
}

// UpdateIncidentStatus updates the status of an existing incident.
func (s *Store) UpdateIncidentStatus(ctx context.Context, id string, status event.IncidentStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, string(status), id)
	if err != nil {
		return fmt.Errorf("sqlite: updating incident status: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("sqlite: incident not found: %s", id)
	}
	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
