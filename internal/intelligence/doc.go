// Package intelligence implements the Threat Engine, providing threat
// intelligence correlation, IOC management, and rule-based scanning.
//
// See SYSTEM_ARCHITECTURE.md §4.6 for full specification.
package intelligence

// TODO: Implement Threat Engine:
//
// Sub-packages:
//   ioc/   — IOC store, ingestion (STIX/TAXII, MISP), and matching
//   yara/  — YARA rule compilation, scanning (file + memory)
//   sigma/ — Sigma rule transpilation to native R3TRIVE rules
//   feeds/ — Threat intelligence feed clients
