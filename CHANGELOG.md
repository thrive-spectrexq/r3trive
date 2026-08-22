# Changelog

All notable changes to the R3TRIVE project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.3] - 2026-08-22

### Added
- **Linux Sensors**: Added `inotify` based file sensor and `/proc/net` based network sensor for Linux hosts.
- **Windows Sensors**: Added ETW-based registry sensor (`Microsoft-Windows-Kernel-Registry`).
- **REST API Server (`internal/api`)**: Built full REST API supporting incident queries, event fetching, and health checks with API key authentication.
- **Enhanced AI RAG**: Added vector embedding support with cosine similarity and MITRE ATT&CK enterprise dataset loading to power the AI Analyst.
- **Storage**: Fixed PostgreSQL driver missing dependency (`jackc/pgx/v5`).
- **E2E Tests**: Added comprehensive integration and E2E test suites for API and sensor pipelines.
- **Docker**: Added multi-stage CGO-enabled build for standard deployments.

---

## [0.1.1] - 2026-07-21

### Added
- **Threat Hunting Engine (`r3trive hunt`)**: Added proactive threat hunting across host processes, disk artifacts, YARA rules, and Sigma rules with MITRE ATT&CK technique filtering (`--technique T1003`).
- **Incident & Binary Investigator (`r3trive investigate`)**: Added deep diagnostic analysis of target binaries (Shannon entropy, SHA256/MD5 hashing, YARA scans, suspicious API detection), running processes (`--pid`), and stored incidents (`--incident`) with composite risk scoring (0–100) and actionable recommendations.
- **IOC Threat Intelligence Engine (`internal/intelligence/ioc`)**: Added fast in-memory lookup for hashes, IP addresses, C2 domains, and URLs, with built-in JSON and CSV threat feed parsers (`LoadJSONFeed`, `LoadCSVFeed`).
- **SIEM & Webhook Exporter (`internal/plugins/exporter`)**: Added SIEM exporter plugin supporting JSON webhooks, Elastic Security, and Splunk HTTP Event Collector (HEC) payload dispatching.
- **YARA Utilities (`r3trive yara scan`)**: Added CLI subcommands for scanning files and directories recursively with YARA rulesets.
- **Sigma Hunting Utilities (`r3trive sigma hunt`)**: Added CLI subcommands for evaluating Sigma detection rules against system log sources, along with sample rules (`rules/sigma/proc_creation_powershell_encoded.yml`).
- **AI Attack Chain Reconstruction (`r3trive attack-chain`)**: Added subcommand to reconstruct multi-stage attack execution sequences from correlated alerts.
- **Automated Response Playbook Engine (`internal/response/playbook`)**: Added configurable playbook execution for automated incident containment (process termination, network blocking, host isolation).
- **Automated GitHub Release Workflow (`.github/workflows/release.yml`)**: Added multi-platform build workflow compiling binaries for Linux (amd64, arm64), Windows (amd64, arm64), and macOS (amd64, arm64) with automated SHA256 `checksums.txt` generation.

### Fixed & Security Hardening
- **Code Security (`gosec`)**: Resolved security scanner findings (`G501`, `G401`, `G304`) with explicit security pragmas for malware hash inspection and CLI file loading.
- **Linting (`golangci-lint`)**: Resolved variable shadowing, `nilerr` return handling, staticcheck tautological condition checks, and slice preallocations.
- **CI Pipeline**: Standardized Go 1.25.x cross-platform matrix testing for Linux and Windows runner environments.

---

[0.1.1]: https://github.com/thrive-spectrexq/r3trive/releases/tag/v0.1.1
