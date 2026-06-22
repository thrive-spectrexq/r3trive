-- R3TRIVE Initial Schema
-- Migration: 001_initial
-- Creates core tables for events, alerts, and incidents.

CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    timestamp   DATETIME NOT NULL,
    host_id     TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    sensor      TEXT NOT NULL,
    data        TEXT NOT NULL,        -- JSON-encoded EventData
    enrichments TEXT,                 -- JSON-encoded enrichments
    chain_hash  TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_host_id ON events(host_id);

CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    timestamp       DATETIME NOT NULL,
    event_id        TEXT NOT NULL REFERENCES events(id),
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.0,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    message         TEXT,
    attack_tactic   TEXT,
    attack_technique TEXT,
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    incident_id     TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id              TEXT PRIMARY KEY,
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',
    severity        TEXT NOT NULL,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    title           TEXT NOT NULL,
    description     TEXT,
    host_ids        TEXT,             -- JSON array
    attack_map      TEXT,             -- JSON array of ATT&CK mappings
    artifact_paths  TEXT,             -- JSON array
    response_actions TEXT,            -- JSON array
    assigned_to     TEXT,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    config_data TEXT NOT NULL,         -- Full YAML config
    checksum    TEXT NOT NULL
);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (1);
