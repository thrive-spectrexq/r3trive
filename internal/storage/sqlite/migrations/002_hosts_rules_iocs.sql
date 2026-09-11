-- Migration: 002_hosts_rules_iocs
-- Adds hosts, rules, playbooks, and IOC tables.

CREATE TABLE IF NOT EXISTS hosts (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT NOT NULL DEFAULT '',
    arch        TEXT NOT NULL DEFAULT '',
    ip_address  TEXT,
    last_seen   DATETIME,
    agent_ver   TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    tags        TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);

CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    confidence  REAL NOT NULL DEFAULT 0.5,
    enabled     INTEGER NOT NULL DEFAULT 1,
    conditions  TEXT NOT NULL,
    attack_tactic    TEXT,
    attack_technique TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbooks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    trigger     TEXT NOT NULL,
    actions     TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ioc_entries (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    tags        TEXT,
    first_seen  DATETIME,
    last_seen   DATETIME,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_entries(type);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_entries(value);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (2);
