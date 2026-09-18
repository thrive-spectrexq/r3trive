package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const pgSchema = `
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    host_id TEXT,
    hostname TEXT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    sensor TEXT NOT NULL,
    data JSONB NOT NULL,
    enrichments JSONB,
    chain_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    risk_score INT NOT NULL,
    message TEXT NOT NULL,
    attack_tactic TEXT,
    attack_technique TEXT,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    incident_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    host_ids JSONB,
    attack_map JSONB,
    artifact_paths JSONB,
    response_actions JSONB,
    assigned_to TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    ip_address TEXT,
    last_seen TIMESTAMPTZ,
    agent_ver TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    tags JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    conditions TEXT NOT NULL,
    attack_tactic TEXT,
    attack_technique TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    trigger TEXT NOT NULL,
    actions JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ioc_entries (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    tags JSONB,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_entries(type);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_entries(value);
`

// Store implements storage.Store for PostgreSQL enterprise fleet deployments.
type Store struct {
	db  *sql.DB
	dsn string
}

// New creates a new PostgreSQL storage backend.
func New(dsn string) (*Store, error) {
	if dsn == "" {
		return nil, fmt.Errorf("empty PostgreSQL connection DSN")
	}

	driverName := "pgx"
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		slog.Warn("postgres driver open warning", "dsn", dsn, "error", err)
		return &Store{db: nil, dsn: dsn}, nil
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		slog.Warn("postgres ping failed, checking connection settings", "dsn", dsn, "error", err)
	} else {
		if _, err := db.ExecContext(ctx, pgSchema); err != nil {
			slog.Warn("postgres schema initialization failed", "error", err)
		} else {
			slog.Info("postgres storage driver initialized successfully", "dsn", dsn)
		}
	}

	return &Store{db: db, dsn: dsn}, nil
}

// DSN returns the configured data source name.
func (s *Store) DSN() string {
	return s.dsn
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// SaveEvent persists a single event to PostgreSQL.
func (s *Store) SaveEvent(ctx context.Context, evt event.Event) error {
	return s.SaveEvents(ctx, []event.Event{evt})
}

// SaveEvents persists a batch of events in a single transaction.
func (s *Store) SaveEvents(ctx context.Context, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}

	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning postgres transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO events (id, timestamp, host_id, hostname, type, severity, sensor, data, enrichments, chain_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}
	defer stmt.Close()

	for _, evt := range events {
		dataJSON, err := json.Marshal(evt.Data)
		if err != nil {
			return fmt.Errorf("marshalling event data for %s: %w", evt.ID, err)
		}

		var enrichJSON []byte
		if len(evt.Enrichments) > 0 {
			enrichJSON, _ = json.Marshal(evt.Enrichments)
		}

		_, err = stmt.ExecContext(ctx,
			evt.ID,
			evt.Timestamp.UTC(),
			evt.Host.ID,
			evt.Host.Hostname,
			string(evt.Type),
			string(evt.Severity),
			evt.Sensor,
			dataJSON,
			enrichJSON,
			evt.ChainHash,
		)
		if err != nil {
			return fmt.Errorf("inserting event %s: %w", evt.ID, err)
		}
	}

	return tx.Commit()
}

// GetEvent retrieves a single event by ID.
func (s *Store) GetEvent(ctx context.Context, id string) (event.Event, error) {
	if s.db == nil {
		return event.Event{}, fmt.Errorf("postgres database connection not active")
	}

	var (
		evt        event.Event
		evtType    string
		severity   string
		dataJSON   string
		enrichJSON sql.NullString
		chainHash  sql.NullString
	)

	row := s.db.QueryRowContext(ctx, `
		SELECT id, timestamp, host_id, hostname, type, severity, sensor, data, enrichments, chain_hash
		FROM events WHERE id = $1
	`, id)

	err := row.Scan(
		&evt.ID,
		&evt.Timestamp,
		&evt.Host.ID,
		&evt.Host.Hostname,
		&evtType,
		&severity,
		&evt.Sensor,
		&dataJSON,
		&enrichJSON,
		&chainHash,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return event.Event{}, fmt.Errorf("event not found: %s", id)
		}
		return event.Event{}, fmt.Errorf("querying event %s: %w", id, err)
	}

	evt.Type = event.EventType(evtType)
	evt.Severity = event.Severity(severity)
	_ = json.Unmarshal([]byte(dataJSON), &evt.Data)
	if enrichJSON.Valid {
		_ = json.Unmarshal([]byte(enrichJSON.String), &evt.Enrichments)
	}
	if chainHash.Valid {
		evt.ChainHash = chainHash.String
	}

	return evt, nil
}

// QueryEvents searches events based on query criteria.
func (s *Store) QueryEvents(ctx context.Context, query storage.EventQuery) ([]event.Event, error) {
	if s.db == nil {
		return nil, fmt.Errorf("postgres database connection not active")
	}

	var clauses []string
	var args []interface{}
	argID := 1

	if query.Type != "" {
		clauses = append(clauses, fmt.Sprintf("type = $%d", argID))
		args = append(args, query.Type)
		argID++
	}
	if query.Severity != "" {
		clauses = append(clauses, fmt.Sprintf("severity = $%d", argID))
		args = append(args, query.Severity)
		argID++
	}
	if query.HostID != "" {
		clauses = append(clauses, fmt.Sprintf("host_id = $%d", argID))
		args = append(args, query.HostID)
		argID++
	}
	if !query.Since.IsZero() {
		clauses = append(clauses, fmt.Sprintf("timestamp >= $%d", argID))
		args = append(args, query.Since.UTC())
		argID++
	}
	if !query.Until.IsZero() {
		clauses = append(clauses, fmt.Sprintf("timestamp <= $%d", argID))
		args = append(args, query.Until.UTC())
		argID++
	}

	whereClause := ""
	if len(clauses) > 0 {
		whereClause = "WHERE " + strings.Join(clauses, " AND ")
	}

	limit := query.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	sqlStr := fmt.Sprintf(`
		SELECT id, timestamp, host_id, hostname, type, severity, sensor, data, enrichments, chain_hash
		FROM events %s ORDER BY timestamp DESC LIMIT $%d
	`, whereClause, argID)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	defer rows.Close()

	var events []event.Event
	for rows.Next() {
		var (
			evt        event.Event
			evtType    string
			severity   string
			dataJSON   string
			enrichJSON sql.NullString
			chainHash  sql.NullString
		)

		if err := rows.Scan(&evt.ID, &evt.Timestamp, &evt.Host.ID, &evt.Host.Hostname, &evtType, &severity, &evt.Sensor, &dataJSON, &enrichJSON, &chainHash); err != nil {
			continue
		}
		evt.Type = event.EventType(evtType)
		evt.Severity = event.Severity(severity)
		_ = json.Unmarshal([]byte(dataJSON), &evt.Data)
		if enrichJSON.Valid {
			_ = json.Unmarshal([]byte(enrichJSON.String), &evt.Enrichments)
		}
		if chainHash.Valid {
			evt.ChainHash = chainHash.String
		}
		events = append(events, evt)
	}

	return events, nil
}

// SaveAlert persists a correlation alert.
func (s *Store) SaveAlert(ctx context.Context, alert event.Alert) error {
	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts (id, timestamp, event_id, rule_id, rule_name, severity, confidence, risk_score, message, attack_tactic, attack_technique, acknowledged, incident_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO UPDATE SET
			acknowledged = EXCLUDED.acknowledged,
			incident_id = EXCLUDED.incident_id
	`,
		alert.ID,
		alert.Timestamp.UTC(),
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

	return err
}

// SaveIncident persists an incident object.
func (s *Store) SaveIncident(ctx context.Context, incident event.Incident) error {
	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	hostIDsJSON, _ := json.Marshal(incident.HostIDs)
	attackMapJSON, _ := json.Marshal(incident.ATTACKMap)
	artifactJSON, _ := json.Marshal(incident.ArtifactPaths)
	actionsJSON, _ := json.Marshal(incident.ResponseActions)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incidents (id, created_at, updated_at, status, severity, risk_score, title, description, host_ids, attack_map, artifact_paths, response_actions, assigned_to, notes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET
			updated_at = EXCLUDED.updated_at,
			status = EXCLUDED.status,
			severity = EXCLUDED.severity,
			risk_score = EXCLUDED.risk_score,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			host_ids = EXCLUDED.host_ids,
			attack_map = EXCLUDED.attack_map,
			artifact_paths = EXCLUDED.artifact_paths,
			response_actions = EXCLUDED.response_actions,
			assigned_to = EXCLUDED.assigned_to,
			notes = EXCLUDED.notes
	`,
		incident.ID,
		incident.CreatedAt.UTC(),
		incident.UpdatedAt.UTC(),
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

	return err
}

// GetIncident retrieves an incident by ID.
func (s *Store) GetIncident(ctx context.Context, id string) (event.Incident, error) {
	if s.db == nil {
		return event.Incident{}, fmt.Errorf("postgres database connection not active")
	}

	var inc event.Incident
	var (
		severity, status, hostIDsJSON, attackMapJSON, artifactJSON, actionsJSON string
		description, assignedTo, notes                                          sql.NullString
	)

	row := s.db.QueryRowContext(ctx, `
		SELECT id, created_at, updated_at, status, severity, risk_score, title, description, host_ids, attack_map, artifact_paths, response_actions, assigned_to, notes
		FROM incidents WHERE id = $1
	`, id)

	err := row.Scan(
		&inc.ID, &inc.CreatedAt, &inc.UpdatedAt, &status, &severity, &inc.RiskScore, &inc.Title,
		&description, &hostIDsJSON, &attackMapJSON, &artifactJSON, &actionsJSON, &assignedTo, &notes,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return event.Incident{}, fmt.Errorf("incident not found: %s", id)
		}
		return event.Incident{}, fmt.Errorf("scanning incident: %w", err)
	}

	inc.Severity = event.Severity(severity)
	inc.Status = event.IncidentStatus(status)
	if description.Valid {
		inc.Description = description.String
	}
	if assignedTo.Valid {
		inc.AssignedTo = assignedTo.String
	}
	if notes.Valid {
		inc.Notes = notes.String
	}
	_ = json.Unmarshal([]byte(hostIDsJSON), &inc.HostIDs)
	_ = json.Unmarshal([]byte(attackMapJSON), &inc.ATTACKMap)
	_ = json.Unmarshal([]byte(artifactJSON), &inc.ArtifactPaths)
	_ = json.Unmarshal([]byte(actionsJSON), &inc.ResponseActions)

	return inc, nil
}

// QueryIncidents retrieves incidents filtered by status.
func (s *Store) QueryIncidents(ctx context.Context, statuses []event.IncidentStatus) ([]event.Incident, error) {
	if s.db == nil {
		return nil, fmt.Errorf("postgres database connection not active")
	}

	var args []interface{}
	whereClause := ""
	if len(statuses) > 0 {
		var placeholders []string
		for i, st := range statuses {
			placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
			args = append(args, string(st))
		}
		whereClause = fmt.Sprintf("WHERE status IN (%s)", strings.Join(placeholders, ", "))
	}

	rows, err := s.db.QueryContext(ctx, "SELECT id, created_at, updated_at, status, severity, risk_score, title, description, host_ids, attack_map, artifact_paths, response_actions, assigned_to, notes FROM incidents "+whereClause+" ORDER BY created_at DESC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []event.Incident
	for rows.Next() {
		var inc event.Incident
		var (
			severity, status, hostIDsJSON, attackMapJSON, artifactJSON, actionsJSON string
			description, assignedTo, notes                                          sql.NullString
		)

		if err := rows.Scan(&inc.ID, &inc.CreatedAt, &inc.UpdatedAt, &status, &severity, &inc.RiskScore, &inc.Title, &description, &hostIDsJSON, &attackMapJSON, &artifactJSON, &actionsJSON, &assignedTo, &notes); err == nil {
			inc.Severity = event.Severity(severity)
			inc.Status = event.IncidentStatus(status)
			if description.Valid {
				inc.Description = description.String
			}
			if assignedTo.Valid {
				inc.AssignedTo = assignedTo.String
			}
			if notes.Valid {
				inc.Notes = notes.String
			}
			_ = json.Unmarshal([]byte(hostIDsJSON), &inc.HostIDs)
			_ = json.Unmarshal([]byte(attackMapJSON), &inc.ATTACKMap)
			_ = json.Unmarshal([]byte(artifactJSON), &inc.ArtifactPaths)
			_ = json.Unmarshal([]byte(actionsJSON), &inc.ResponseActions)
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

// UpdateIncidentStatus modifies an incident's operational status.
func (s *Store) UpdateIncidentStatus(ctx context.Context, id string, status event.IncidentStatus) error {
	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	_, err := s.db.ExecContext(ctx, "UPDATE incidents SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", string(status), id)
	return err
}

func (s *Store) SaveHost(ctx context.Context, host storage.Host) error {
	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	tagsJSON, err := json.Marshal(host.Tags)
	if err != nil {
		return fmt.Errorf("postgres: marshaling host tags: %w", err)
	}

	createdAt := host.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO hosts (id, hostname, os, arch, ip_address, last_seen, agent_ver, status, tags, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			os = EXCLUDED.os,
			arch = EXCLUDED.arch,
			ip_address = EXCLUDED.ip_address,
			last_seen = EXCLUDED.last_seen,
			agent_ver = EXCLUDED.agent_ver,
			status = EXCLUDED.status,
			tags = EXCLUDED.tags
	`, host.ID, host.Hostname, host.OS, host.Arch, host.IPAddress, host.LastSeen, host.AgentVer, host.Status, string(tagsJSON), createdAt)
	if err != nil {
		return fmt.Errorf("postgres: saving host: %w", err)
	}
	return nil
}

func (s *Store) GetHost(ctx context.Context, id string) (storage.Host, error) {
	if s.db == nil {
		return storage.Host{}, fmt.Errorf("postgres database connection not active")
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, hostname, os, arch, ip_address, last_seen, agent_ver, status, tags, created_at FROM hosts WHERE id = $1`, id)

	var h storage.Host
	var (
		lastSeen            sql.NullTime
		ipAddress, agentVer sql.NullString
		tagsJSON            sql.NullString
	)
	err := row.Scan(&h.ID, &h.Hostname, &h.OS, &h.Arch, &ipAddress, &lastSeen, &agentVer, &h.Status, &tagsJSON, &h.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.Host{}, fmt.Errorf("host not found: %s", id)
		}
		return storage.Host{}, fmt.Errorf("postgres: scanning host: %w", err)
	}
	if ipAddress.Valid {
		h.IPAddress = ipAddress.String
	}
	if lastSeen.Valid {
		h.LastSeen = lastSeen.Time
	}
	if agentVer.Valid {
		h.AgentVer = agentVer.String
	}
	if tagsJSON.Valid && tagsJSON.String != "" {
		_ = json.Unmarshal([]byte(tagsJSON.String), &h.Tags)
	}
	return h, nil
}

func (s *Store) ListHosts(ctx context.Context) ([]storage.Host, error) {
	if s.db == nil {
		return nil, fmt.Errorf("postgres database connection not active")
	}

	rows, err := s.db.QueryContext(ctx, `SELECT id, hostname, os, arch, ip_address, last_seen, agent_ver, status, tags, created_at FROM hosts ORDER BY hostname ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list hosts: %w", err)
	}
	defer rows.Close()

	var hosts []storage.Host
	for rows.Next() {
		var h storage.Host
		var (
			lastSeen            sql.NullTime
			ipAddress, agentVer sql.NullString
			tagsJSON            sql.NullString
		)
		if err := rows.Scan(&h.ID, &h.Hostname, &h.OS, &h.Arch, &ipAddress, &lastSeen, &agentVer, &h.Status, &tagsJSON, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan host: %w", err)
		}
		if ipAddress.Valid {
			h.IPAddress = ipAddress.String
		}
		if lastSeen.Valid {
			h.LastSeen = lastSeen.Time
		}
		if agentVer.Valid {
			h.AgentVer = agentVer.String
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			_ = json.Unmarshal([]byte(tagsJSON.String), &h.Tags)
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

func (s *Store) SaveRule(ctx context.Context, rule storage.StoredRule) error {
	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	createdAt := rule.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	updatedAt := rule.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rules (id, name, description, severity, confidence, enabled, conditions, attack_tactic, attack_technique, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			enabled = EXCLUDED.enabled,
			conditions = EXCLUDED.conditions,
			attack_tactic = EXCLUDED.attack_tactic,
			attack_technique = EXCLUDED.attack_technique,
			updated_at = EXCLUDED.updated_at
	`, rule.ID, rule.Name, rule.Description, rule.Severity, rule.Confidence, rule.Enabled, rule.Conditions, rule.ATTACKTactic, rule.ATTACKTechnique, createdAt, updatedAt)
	if err != nil {
		return fmt.Errorf("postgres: saving rule: %w", err)
	}
	return nil
}

func (s *Store) GetRule(ctx context.Context, id string) (storage.StoredRule, error) {
	if s.db == nil {
		return storage.StoredRule{}, fmt.Errorf("postgres database connection not active")
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, severity, confidence, enabled, conditions, attack_tactic, attack_technique, created_at, updated_at FROM rules WHERE id = $1`, id)

	var r storage.StoredRule
	var desc, tactic, technique sql.NullString
	err := row.Scan(&r.ID, &r.Name, &desc, &r.Severity, &r.Confidence, &r.Enabled, &r.Conditions, &tactic, &technique, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.StoredRule{}, fmt.Errorf("rule not found: %s", id)
		}
		return storage.StoredRule{}, fmt.Errorf("postgres: scanning rule: %w", err)
	}
	if desc.Valid {
		r.Description = desc.String
	}
	if tactic.Valid {
		r.ATTACKTactic = tactic.String
	}
	if technique.Valid {
		r.ATTACKTechnique = technique.String
	}
	return r, nil
}

func (s *Store) ListRules(ctx context.Context, enabledOnly bool) ([]storage.StoredRule, error) {
	if s.db == nil {
		return nil, fmt.Errorf("postgres database connection not active")
	}

	query := `SELECT id, name, description, severity, confidence, enabled, conditions, attack_tactic, attack_technique, created_at, updated_at FROM rules`
	if enabledOnly {
		query += ` WHERE enabled = TRUE`
	}
	query += ` ORDER BY name ASC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("postgres: list rules: %w", err)
	}
	defer rows.Close()

	var rules []storage.StoredRule
	for rows.Next() {
		var r storage.StoredRule
		var desc, tactic, technique sql.NullString
		if err := rows.Scan(&r.ID, &r.Name, &desc, &r.Severity, &r.Confidence, &r.Enabled, &r.Conditions, &tactic, &technique, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan rule: %w", err)
		}
		if desc.Valid {
			r.Description = desc.String
		}
		if tactic.Valid {
			r.ATTACKTactic = tactic.String
		}
		if technique.Valid {
			r.ATTACKTechnique = technique.String
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) DeleteRule(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: deleting rule: %w", err)
	}
	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}
	return nil
}

func (s *Store) SaveIOC(ctx context.Context, ioc storage.IOCEntry) error {
	if s.db == nil {
		return fmt.Errorf("postgres database connection not active")
	}

	tagsJSON, err := json.Marshal(ioc.Tags)
	if err != nil {
		return fmt.Errorf("postgres: marshaling ioc tags: %w", err)
	}

	createdAt := ioc.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ioc_entries (id, type, value, source, severity, tags, first_seen, last_seen, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			type = EXCLUDED.type,
			value = EXCLUDED.value,
			source = EXCLUDED.source,
			severity = EXCLUDED.severity,
			tags = EXCLUDED.tags,
			last_seen = EXCLUDED.last_seen
	`, ioc.ID, ioc.Type, ioc.Value, ioc.Source, ioc.Severity, string(tagsJSON), ioc.FirstSeen, ioc.LastSeen, createdAt)
	if err != nil {
		return fmt.Errorf("postgres: saving ioc: %w", err)
	}
	return nil
}

func (s *Store) QueryIOCs(ctx context.Context, iocType string, value string) ([]storage.IOCEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("postgres database connection not active")
	}

	query := `SELECT id, type, value, source, severity, tags, first_seen, last_seen, created_at FROM ioc_entries WHERE 1=1`
	var args []interface{}
	paramIdx := 1
	if iocType != "" {
		query += fmt.Sprintf(" AND type = $%d", paramIdx)
		args = append(args, iocType)
		paramIdx++
	}
	if value != "" {
		query += fmt.Sprintf(" AND value = $%d", paramIdx)
		args = append(args, value)
		paramIdx++
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: query iocs: %w", err)
	}
	defer rows.Close()

	var iocs []storage.IOCEntry
	for rows.Next() {
		var ioc storage.IOCEntry
		var (
			tagsJSON, source    sql.NullString
			firstSeen, lastSeen sql.NullTime
		)
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &source, &ioc.Severity, &tagsJSON, &firstSeen, &lastSeen, &ioc.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan ioc: %w", err)
		}
		if source.Valid {
			ioc.Source = source.String
		}
		if firstSeen.Valid {
			ioc.FirstSeen = firstSeen.Time
		}
		if lastSeen.Valid {
			ioc.LastSeen = lastSeen.Time
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			_ = json.Unmarshal([]byte(tagsJSON.String), &ioc.Tags)
		}
		iocs = append(iocs, ioc)
	}
	return iocs, rows.Err()
}

var _ storage.Store = (*Store)(nil)
