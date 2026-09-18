// Package postgres implements the storage.Store interface using PostgreSQL
// for enterprise fleet and cluster deployments.
//
// Capabilities include:
// - Events, alerts, and incidents persistence
// - Hosts registration and status tracking
// - Correlation rules and playbooks storage
// - IOC entries query and persistence
// - Connection pooling and automatic schema initialization
package postgres
