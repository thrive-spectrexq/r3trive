# Changelog

All notable changes to the R3TRIVE project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.7] - 2026-09-12

### Added
- **Statistical & Heuristic Anomaly Detectors**: Implemented C2 Beaconing detection via Coefficient of Variation (CV < 0.15), DNS Tunneling detection using subdomain Shannon entropy (> 3.8 bits/byte) and query volume spikes, Ransomware behavioral burst detection (> 7.2 bits/byte across sliding modification windows), streaming Isolation Forest online anomaly scoring, and UEBA baseline profiling for user/process activity.
- **Platform Sensor Completeness**:
  - **Native Windows Service Sensor**: Implemented native Service Control Manager polling (`OpenSCManager`, `EnumServicesStatusEx`) emitting `event.ServiceCreate`, `event.ServiceStart`, and `event.ServiceStop`.
  - **Linux eBPF CO-RE Hardening & systemd Watcher**: Added kernel BTF discovery (`/sys/kernel/btf/vmlinux`) with automatic `/proc` polling fallback for kernels < 5.4, and systemd service state tracking.
  - **macOS Endpoint Security Framework**: Implemented ESF-aligned process, file, and network sensor abstractions with user-space sysctl/lsof/kqueue fallbacks.
- **Correlation & Attack Chain Validation**: Implemented MITRE ATT&CK kill-chain progression validation, consistent hash rings for distributed routing, and SHA-256 alert deduplication fingerprinting.
- **Plugin Ecosystem**: Formalized versioned Go Plugin SDK (`CurrentAPIVersion = "1.0.0"`) and implemented six builtin integration plugins: Splunk HEC forwarder, Elasticsearch bulk indexer, Jira issue creator, PagerDuty v2 event trigger, VirusTotal reputation checker, and MISP threat sharing client.
- **AI Action Recommendation Engine**: Added `ActionRecommender` providing automated confidence scoring, prerequisite verification, and paired rollback actions for incident remediation.
- **OpenAPI 3.0 & Swagger UI**: Embedded OpenAPI 3.0 specification served at `/api/v1/openapi.json` with interactive Swagger UI served at `/swagger`.
- **Database Retention & Archival**: Added background data lifecycle manager with compressed JSONL gzip archival for audit compliance.
- **Anti-Tamper & Security Hardening**: Added memory wiping primitives (`ZeroBytes`), anti-swapping RAM locking (`VirtualLock` on Windows, `unix.Mlock` on POSIX), and binary self-integrity SHA-256 checksum verification.
- **Regression Suite & High-Throughput Benchmarks**: Added detection rule regression test suite, regex precompilation benchmark, and high-rate event pipeline load benchmark (16M+ burst events/sec at 80.41 ns/op, 0 allocs/op).
- **Documentation & Verification**: Added `docs/troubleshooting.md`, `docs/plugin_tutorial.md`, and automated CI documentation drift checking script `scripts/verify_docs_drift.ps1`.

### Changed & Security Upgrades
- **Dependency Upgrades**:
  - Upgraded `google.golang.org/grpc` from 1.83.1 to 1.83.2, resolving high-severity advisory GHSA-2v4p-qf9q-27wj (Dependabot Alert #2).
  - Upgraded OpenTelemetry SDK to 1.46.0.
  - Upgraded GitHub CodeQL Action to 4.37.9.
  - Configured Dependabot grouping and conventional commit prefixes (`chore(deps)`).
- **Static Analysis & Gosec Compliance**: Resolved Gosec G404 non-crypto random findings, G304 file path sanitation, and errorlint compliance.

---

## [0.1.6] - 2026-09-12

### Added
- **Native Windows Network Sensor**: Implemented unprivileged TCP and UDP connection monitoring in `internal/detection/sensor/windows/network.go` using pure Go standard library `syscall` with `iphlpapi.dll` (`GetExtendedTcpTable`, `GetExtendedUdpTable`). Emits `event.NetworkConnect` and `event.NetworkListen` events with process IDs, local/remote IP addresses, and ports without requiring Administrator/ETW privileges.
- **Native Windows File Sensor**: Implemented unprivileged filesystem change monitoring in `internal/detection/sensor/windows/file.go` using Win32 directory change notifications (`ReadDirectoryChangesW`) to observe critical paths (`C:\Windows\System32`, `C:\Users\Public`, `C:\ProgramData`). Emits `event.FileCreate`, `event.FileModify`, and `event.FileDelete` events.
- **Real-Time Incident Aggregator**: Implemented `IncidentAggregator` in `internal/correlation/aggregator.go` with sliding temporal correlation windows (15-minute default). Groups alerts by composite keys (`host_id + primary_entity`), dynamically recalculates risk scores via `CalculateIncidentScore`, escalates incident severity when alert counts surge, merges deduplicated ATT&CK technique sets, and persists incidents to SQLite/PostgreSQL.
- **Automated Alert Persistence in Monitor Pipeline**: Connected alert handling in `internal/detection/pipeline/pipeline.go` directly to persistent storage, ensuring alerts and correlated incidents are queryable across restarts and via REST API.

### Improved & Documentation
- **Comprehensive Documentation Suite Overhaul**: Updated and synchronized all technical specifications and MkDocs pages across `SYSTEM_ARCHITECTURE.md`, `DETECTION_ENGINE_SPEC.md`, `RULE_ENGINE_SPEC.md`, `DATABASE_SCHEMA.md`, `SOC_WORKFLOW.md`, `API_REFERENCE.md`, `CONTRIBUTING.md`, and `README.md`.
- **API & CLI Documentation Alignment**: Fully documented `002_hosts_rules_iocs.sql` database migration, condition operators & reflection field lookup, unprivileged Win32 sensors, `ActionExecutor`, automated defense daemon (`r3trive defend`), proactive threat hunting (`r3trive hunt`, `r3trive investigate`), and AI Analyst subcommands.
- **Documentation Web Application**: Verified seamless cross-linking and zero broken paths for GitHub Pages deployment.

---

## [0.1.5] - 2026-09-12

### Added
- **Native Windows Process Sensor**: Implemented native Windows process monitoring in `internal/detection/sensor/windows/process.go` using pure standard library `syscall` Toolhelp32 APIs (`CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`). Features baseline snapshotting to avoid startup floods, differential polling for process creation detection, parent process name resolution, and thread-safe atomic metrics.
- **Cross-Platform Sensor Compatibility**: Added `internal/detection/sensor/windows/sensor_other.go` with `!windows` build tags to ensure seamless compilation across Linux and macOS environments.
- **Centralized Windows Sensor Helpers**: Added `internal/detection/sensor/windows/helpers.go` providing shared `getHostname`, `extractNameFromPath`, and `toInt` functions.
- **Response Action API Execution**: Connected `/api/v1/response/execute` to the response engine via the `ActionExecutor` interface, enabling real and dry-run containment actions (kill process, block IP, quarantine file, isolate host) over authenticated HTTP requests.
- **CLI Serve Response Integration**: Added `--dry-run` flag (defaulting to true) to `r3trive serve` command to initialize and wire `response.Engine` directly into the HTTP API server.
- **Documentation Website Deployment**: Added GitHub Pages documentation pipeline (`.github/workflows/docs.yml`) using Material for MkDocs with unified left-sidebar navigation and full project guides.

### Improved & Optimized
- **Correlation Engine Regex Pre-Compilation**: Added thread-safe regular expression caching to `internal/correlation/engine.go` (`regexCache`). Rule condition regexes are pre-compiled during rule loading rather than recompiled on every incoming event.
- **REST API JSON Response Consistency**: Fixed handlers for `/hosts`, `/rules`, and `/iocs` to ensure empty query results serialize as empty JSON arrays `[]` instead of `null`.
- **Test Coverage Expansion**: Added unit and lifecycle tests for Windows process sensor (`process_test.go`) and response action execution HTTP handler (`response_test.go`).

---

## [0.1.4] - 2026-09-11

### Added
- **REST API Endpoints (`/hosts`, `/rules`, `/iocs`, `/response`)**: Added full CRUD API handlers for host registration, correlation rule management, IOC querying, and response action execution via REST API.
- **Database Schema Migration (`002_hosts_rules_iocs.sql`)**: Added `hosts`, `rules`, `playbooks`, and `ioc_entries` tables with proper indexes and foreign key constraints.
- **Storage Interface Expansion**: Extended `Store` interface with `SaveHost`, `GetHost`, `ListHosts`, `SaveRule`, `GetRule`, `ListRules`, `DeleteRule`, `SaveIOC`, and `QueryIOCs` methods, with full SQLite implementations.
- **Regex Correlation Operator**: Added `regex` operator support to the correlation engine condition matcher, enabling regex-based pattern matching in detection rules.
- **Reflection-Based Field Resolver**: Replaced hardcoded `extractField` switch statement with a generic reflection-based dotted-path resolver that walks any `Event` struct tree via JSON tags.
- **Comprehensive Test Coverage**: Added 25+ new test cases covering regex matching (valid/invalid/no-match), all correlation operators (`contains`, `oneOf`, unknown), field extraction via reflection, PID validation, IP validation, quarantine edge cases, and unknown action handling.

### Fixed & Security Hardening
- **Correlation Engine Bug (`regex` operator)**: Fixed silent failure where rules using `operator: regex` would never trigger because the `matchCondition` switch statement was missing the `regex` case.
- **PID Validation**: Added positive integer validation before executing `sysKillProcess` — negative and zero PIDs are now rejected with clear error messages.
- **IP Address Validation**: Added `net.ParseIP` validation in both Windows (`netsh`) and POSIX (`iptables`) IP blocking actions to prevent malformed addresses from reaching system commands.
- **Quarantine Permissions Hardening**: Changed Windows quarantine `icacls` permission failure from a silent warning to a returned error, preventing false-positive quarantine reports when file permissions cannot be secured.
- **String Search Simplification**: Replaced custom `containsStr`/`searchStr` functions with stdlib `strings.Contains`.

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

[0.1.4]: https://github.com/thrive-spectrexq/r3trive/releases/tag/v0.1.4
[0.1.1]: https://github.com/thrive-spectrexq/r3trive/releases/tag/v0.1.1
