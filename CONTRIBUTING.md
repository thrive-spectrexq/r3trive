# CONTRIBUTING.md

**Contributing to R3TRIVE**
Version: 1.0.0

---

## Table of Contents

1. [Welcome](#1-welcome)
2. [Code of Conduct](#2-code-of-conduct)
3. [Ways to Contribute](#3-ways-to-contribute)
4. [Development Setup](#4-development-setup)
5. [Project Structure](#5-project-structure)
6. [Coding Standards](#6-coding-standards)
7. [Testing Requirements](#7-testing-requirements)
8. [Detection Rule Contributions](#8-detection-rule-contributions)
9. [Plugin Contributions](#9-plugin-contributions)
10. [Pull Request Process](#10-pull-request-process)
11. [Security Vulnerability Reporting](#11-security-vulnerability-reporting)
12. [Release Process](#12-release-process)
13. [Recognition](#13-recognition)

---

## 1. Welcome

R3TRIVE is built by the security community, for the security community. We welcome contributions of all kinds: code, detection rules, documentation, bug reports, and ideas.

Before contributing, please read this document fully. It exists to help us maintain quality and consistency as the project grows.

**If you're new to open source contribution**, the sections most relevant to you are:
- [Ways to Contribute](#3-ways-to-contribute) — what kind of contributions we accept
- [Development Setup](#4-development-setup) — getting your environment ready
- [Pull Request Process](#10-pull-request-process) — how to submit your work

---

## 2. Code of Conduct

### 2.1 Our Standards

R3TRIVE is a professional security project. We expect all contributors to:

- Be respectful and constructive in all interactions
- Focus criticism on ideas and code, not people
- Accept feedback graciously
- Assume good faith from other contributors

### 2.2 Not Acceptable

- Personal attacks, harassment, or discriminatory language
- Sharing personal information of others without consent
- Submitting code intended to harm systems (even as a joke)
- Deliberately misleading the project or its users

### 2.3 Enforcement

Violations can be reported to conduct@r3trive.io. Maintainers reserve the right to remove contributions and ban contributors who violate these standards.

---

## 3. Ways to Contribute

### 3.1 Bug Reports

Open a GitHub issue with:

```markdown
**R3TRIVE version:** (from `r3trive version`)
**OS and version:** (e.g., Ubuntu 22.04, Windows Server 2022)
**Go version:** (from `go version`)

**What happened:**
[Clear description of the bug]

**What you expected:**
[What should have happened]

**Steps to reproduce:**
1. 
2. 
3. 

**Relevant output:**
```
[Paste relevant logs, error messages, or command output]
```

**Additional context:**
[Any other relevant information]
```

### 3.2 Feature Requests

Open a GitHub issue labeled `enhancement` with:
- Clear description of the problem the feature solves
- Proposed solution or approach
- Alternatives you've considered
- Whether you're willing to implement it yourself

### 3.3 Code Contributions

See [Development Setup](#4-development-setup) and [Pull Request Process](#10-pull-request-process).

Areas where we especially welcome contributions:
- New platform sensors (FreeBSD, OpenBSD, ARM)
- Detection rule authoring (behavioral and Sigma)
- Plugin implementations (new SIEM, ticketing, intelligence sources)
- Performance improvements with benchmarks
- Documentation improvements and examples
- Test coverage improvements

### 3.4 Detection Rule Contributions

Detection rules are one of the highest-value contributions to R3TRIVE. See [Detection Rule Contributions](#8-detection-rule-contributions) for the dedicated process.

### 3.5 Documentation

Documentation lives in `/docs/` and is written in Markdown. Good documentation contributions include:
- Fixing unclear explanations or outdated information
- Adding examples to existing docs
- Translating documentation (for major languages)
- Adding troubleshooting entries from your experience

---

## 4. Development Setup

### 4.1 Prerequisites

| Tool | Version | Install |
|---|---|---|
| Go | 1.22+ | https://go.dev/dl/ |
| Rust | 1.75+ | https://rustup.rs/ |
| Python | 3.11+ | https://python.org |
| Docker | 24+ | https://docs.docker.com/get-docker/ |
| Make | Any | System package manager |
| golangci-lint | 1.57+ | https://golangci-lint.run/ |
| protoc | 3.25+ | https://grpc.io/docs/protoc-installation/ |

### 4.2 Clone and Build

```bash
git clone https://github.com/r3trive/r3trive.git
cd r3trive

# Install Go dependencies
go mod download

# Install development tools
make install-tools

# Build all targets
make build

# Run tests
make test

# Run linter
make lint
```

### 4.3 Platform-Specific Setup

#### Linux (recommended for development)

```bash
# Install eBPF development dependencies
sudo apt-get install -y \
  linux-headers-$(uname -r) \
  libbpf-dev \
  clang \
  llvm

# Build with eBPF support
make build TAGS="ebpf"

# Run as root (required for sensor testing)
sudo ./dist/r3trive monitor --dev
```

#### macOS (limited sensor support)

```bash
# macOS sensors require System Extension entitlement (not available for dev builds)
# Development mode uses a mock sensor
make build TAGS="mock_sensors"
./dist/r3trive monitor --dev --sensor-mode mock
```

#### Windows

```powershell
# Install MSYS2 for Make support
# Install Windows SDK for ETW bindings

make build TAGS="windows_etw"
```

### 4.4 Environment Variables

```bash
# Required for testing with a live AI backend
export OPENAI_API_KEY="sk-..."

# Or use local Ollama (recommended)
export R3TRIVE_AI_BACKEND="ollama"
export R3TRIVE_AI_OLLAMA_HOST="http://localhost:11434"

# Test database (defaults to SQLite in /tmp)
export R3TRIVE_DB_PATH="/tmp/r3trive-dev.db"

# Enable debug logging
export R3TRIVE_LOG_LEVEL="debug"
```

### 4.5 Running in Development Mode

```bash
# Start with verbose logging and mock sensors
./dist/r3trive monitor --dev --log-level debug

# Generate test events
make emit-test-events

# Run with a specific config
./dist/r3trive --config ./configs/dev.yaml monitor
```

---

## 5. Project Structure

```
r3trive/
│
├── cmd/r3trive/               # CLI entry point (cobra commands)
│   ├── main.go
│   ├── monitor.go
│   ├── hunt.go
│   ├── investigate.go
│   ├── defend.go
│   ├── audit.go
│   ├── ai.go                  # explain, summarize, generate-rule, ask
│   ├── yara.go
│   ├── sigma.go
│   └── ...
│
├── internal/                  # Non-exported packages (core logic)
│   ├── detection/             # Detection Core
│   │   ├── sensor/            # Platform-specific sensors
│   │   │   ├── linux/         # eBPF sensors
│   │   │   ├── windows/       # ETW sensors
│   │   │   └── macos/         # ESF sensors
│   │   ├── normalizer/        # Event normalization
│   │   ├── enricher/          # Event enrichment
│   │   └── pipeline/          # Event pipeline orchestration
│   │
│   ├── correlation/           # Correlation Engine
│   │   ├── engine.go
│   │   ├── window.go          # Temporal window management
│   │   ├── incident.go        # Incident creation/management
│   │   └── scorer.go          # Risk scoring
│   │
│   ├── response/              # Response Core
│   │   ├── engine.go
│   │   ├── actions/           # Individual action implementations
│   │   └── playbook/          # Playbook engine
│   │
│   ├── ai/                    # AI Analyst Layer
│   │   ├── analyst.go
│   │   ├── context/           # Context builder
│   │   ├── prompt/            # Prompt templates
│   │   ├── router/            # Model router
│   │   ├── rag/               # RAG pipeline
│   │   └── parser/            # Response parser
│   │
│   ├── intelligence/          # Threat Engine
│   │   ├── ioc/               # IOC store and matching
│   │   ├── yara/              # YARA integration
│   │   ├── sigma/             # Sigma integration
│   │   └── feeds/             # Threat feed clients
│   │
│   ├── plugins/               # Plugin Manager
│   │   ├── manager.go
│   │   ├── loader.go
│   │   └── sandbox/           # Plugin sandboxing
│   │
│   ├── storage/               # Storage Layer
│   │   ├── db.go              # Database interface
│   │   ├── sqlite/            # SQLite implementation
│   │   ├── postgres/          # PostgreSQL implementation
│   │   └── migrations/        # SQL migration files
│   │
│   ├── telemetry/             # OpenTelemetry integration
│   │
│   └── config/                # Configuration management
│
├── pkg/                       # Exported packages (public API / SDK)
│   ├── event/                 # Event types and schema
│   ├── rule/                  # Rule types and DSL
│   ├── yara/                  # YARA wrapper
│   ├── sigma/                 # Sigma transpiler
│   └── utils/                 # Shared utilities
│
├── rules/                     # Detection rules
│   ├── behavioral/            # Behavioral detection rules (YAML)
│   ├── yara/                  # YARA rule files
│   ├── sigma/                 # Sigma rule files
│   ├── correlation/           # Correlation rules (YAML)
│   ├── macros/                # Reusable macro definitions
│   └── custom/                # User custom rules (not shipped)
│
├── docs/                      # Documentation
├── configs/                   # Example configuration files
├── plugins/                   # First-party plugin source
├── tests/
│   ├── integration/           # Integration tests
│   ├── e2e/                   # End-to-end tests
│   └── fixtures/              # Test event fixtures
├── scripts/                   # Build and maintenance scripts
└── deployments/               # Deployment artifacts
    ├── docker/
    ├── kubernetes/
    ├── systemd/
    └── selinux/
```

---

## 6. Coding Standards

### 6.1 Go Standards

We follow [Effective Go](https://go.dev/doc/effective_go) and the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

**Specific requirements:**

```go
// DO: Document all exported symbols
// Package detection provides the core event detection pipeline.
package detection

// Sensor is implemented by all platform-specific event collection modules.
type Sensor interface {
    Name() string
    // ...
}

// DON'T: Leave exported symbols undocumented
type Sensor interface {
    Name() string
}
```

**Error handling:**
```go
// DO: Wrap errors with context using fmt.Errorf + %w
func loadRule(path string) (*Rule, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("loadRule: reading %s: %w", path, err)
    }
    // ...
}

// DON'T: Swallow errors or return raw errors without context
func loadRule(path string) (*Rule, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err  // no context
    }
}
```

**Concurrency:**
```go
// DO: Use context for cancellation; close channels from the sender
// DO: Document goroutine lifetimes in comments
// DON'T: Use global mutexes; prefer message passing via channels
// DON'T: Spawn goroutines without a defined termination path
```

**Logging:**
```go
// DO: Use structured logging (slog)
slog.Info("sensor started", "sensor", s.Name(), "platform", runtime.GOOS)
slog.Error("rule evaluation failed", "rule_id", rule.ID, "error", err)

// DON'T: Use fmt.Printf or log.Printf in library code
fmt.Printf("starting sensor %s\n", s.Name())
```

### 6.2 Rust Standards

Rust is used for performance-critical modules. Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).

```rust
// DO: Handle errors explicitly; no unwrap() in library code
fn scan_file(path: &Path) -> Result<ScanResult, ScanError> {
    let data = fs::read(path)?;
    // ...
}

// DON'T: Unwrap in production paths
let data = fs::read(path).unwrap();  // panics in production

// DO: Forbid unsafe code at module level where possible
#![forbid(unsafe_code)]
```

### 6.3 Python Standards

Python is used for AI tooling and scripts. Follow PEP 8 + type hints.

```python
# DO: Use type hints on all functions
def enrich_event(event: Event, config: EnrichConfig) -> EnrichedEvent:
    ...

# DO: Use dataclasses or pydantic for structured data
@dataclass
class EnrichConfig:
    geoip_db_path: str
    timeout_seconds: float = 5.0
```

### 6.4 Linting

All code must pass the configured linters before merge:

```bash
# Go
golangci-lint run ./...

# Python
ruff check .
mypy .

# Rust
cargo clippy -- -D warnings
```

Lint configuration is in `.golangci.yml`, `pyproject.toml`, and `.clippy.toml`. Do not disable linter warnings without a comment explaining why.

---

## 7. Testing Requirements

### 7.1 Test Coverage Requirements

| Package | Minimum Coverage |
|---|---|
| `internal/detection` | 80% |
| `internal/correlation` | 85% |
| `internal/response` | 80% |
| `internal/ai` | 70% |
| `internal/storage` | 90% |
| `pkg/*` | 90% |

Check coverage:
```bash
make coverage
# Opens coverage report in browser
```

### 7.2 Test Types

**Unit tests** (`*_test.go` in same package):
- Cover individual functions and methods
- Must be fast (< 1s each) and deterministic
- No network calls, file system writes to non-temp paths, or time dependencies without mocking

**Integration tests** (`tests/integration/`):
- Test interaction between multiple components
- May use test databases and temp directories
- Run with `make test-integration`

**End-to-end tests** (`tests/e2e/`):
- Full system tests with real sensors (Linux only, requires root)
- Run in CI on dedicated test machines
- Run locally with `make test-e2e` (requires elevated privileges)

### 7.3 Writing Good Tests

```go
// DO: Use table-driven tests for multiple cases
func TestEvaluateCondition(t *testing.T) {
    tests := []struct {
        name      string
        condition Condition
        event     Event
        want      bool
    }{
        {
            name:      "exact match",
            condition: Condition{Field: "data.name", Op: OpEq, Value: "powershell.exe"},
            event:     Event{Data: map[string]any{"name": "powershell.exe"}},
            want:      true,
        },
        {
            name:      "case sensitive mismatch",
            condition: Condition{Field: "data.name", Op: OpEq, Value: "powershell.exe"},
            event:     Event{Data: map[string]any{"name": "PowerShell.exe"}},
            want:      false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := EvaluateCondition(tt.condition, tt.event)
            if got != tt.want {
                t.Errorf("EvaluateCondition() = %v, want %v", got, tt.want)
            }
        })
    }
}

// DON'T: Write tests with magic numbers and no explanation
func TestSomething(t *testing.T) {
    result := Process(Event{Type: "proc", Data: map[string]any{"x": 42}})
    if result != 7 {
        t.Error("wrong")
    }
}
```

### 7.4 Test Fixtures

Event fixtures for testing live in `tests/fixtures/`. When adding new rule tests, add corresponding fixture files:

```bash
# Add a true positive fixture
tests/fixtures/rules/R3T-EXEC-001_tp_encoded_powershell.json

# Add a false positive fixture  
tests/fixtures/rules/R3T-EXEC-001_fp_admin_automation.json
```

---

## 8. Detection Rule Contributions

Detection rules are reviewed by the security team for accuracy and false positive risk before merging.

### 8.1 Rule Quality Requirements

Before submitting a rule:

- [ ] Rule has a clear, accurate description explaining what it detects and why it's suspicious
- [ ] Rule has been tested against at least 3 true positive event fixtures
- [ ] Rule has been tested against at least 3 false positive event fixtures (known-good activity)
- [ ] Rule uses macros where available instead of hardcoded lists
- [ ] ATT&CK technique mapping is correct (verify at attack.mitre.org)
- [ ] References include at least one public source (blog post, ATT&CK page, CVE)
- [ ] Confidence level is accurately set (don't claim 0.95 for a broad pattern)
- [ ] Severity is appropriate (don't set everything to Critical)

### 8.2 Submitting Rules

```bash
# Validate rule syntax and test fixtures
r3trive rule validate ./rules/behavioral/my_new_rule.yaml
r3trive rule test --rule ./rules/behavioral/my_new_rule.yaml

# Run against the full rule test suite to check for interference
make test-rules
```

Rules go in:
- `rules/behavioral/` — behavioral detection rules
- `rules/correlation/` — multi-event correlation rules
- `rules/yara/community/` — YARA rules (credit original author)

### 8.3 Rule ID Assignment

Core rules use `R3T-{CATEGORY}-{NNN}`. Community-contributed rules use `COMM-{CATEGORY}-{NNN}`. IDs are assigned by maintainers during PR review. Use `DRAFT-{descriptive-name}` as a placeholder.

### 8.4 Sigma Rule Contributions

Sigma rules should be submitted to the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) repository directly. R3TRIVE auto-syncs from SigmaHQ. Only add Sigma rules to R3TRIVE if they are R3TRIVE-specific and not appropriate for SigmaHQ.

---

## 9. Plugin Contributions

First-party plugin contributions (to be maintained under the `r3trive` GitHub organization) must meet a higher bar:

- Full test coverage (85%+)
- Integration test with real external service (or approved mock)
- Security review by a maintainer
- Documentation following the PLUGIN_SDK.md format
- Signed with a registered developer key

See [PLUGIN_SDK.md](PLUGIN_SDK.md) for plugin development documentation.

Third-party plugins (maintained in your own repository) don't require our approval but we encourage following the same standards and registering with the plugin directory.

---

## 10. Pull Request Process

### 10.1 Before You Submit

- [ ] Your branch is up to date with `main`
- [ ] All tests pass (`make test`)
- [ ] Linter passes (`make lint`)
- [ ] New code has adequate test coverage (`make coverage`)
- [ ] Documentation is updated if you changed public interfaces
- [ ] CHANGELOG.md entry added (for user-facing changes)
- [ ] Rule fixtures included (for detection rule changes)

### 10.2 PR Template

When opening a PR, fill in the provided template:

```markdown
## Summary
[What does this PR do? Why is it needed?]

## Changes
- [List of significant changes]

## Testing
[How did you test this? What scenarios did you cover?]

## Type
- [ ] Bug fix
- [ ] Feature
- [ ] Detection rule
- [ ] Documentation
- [ ] Refactor
- [ ] Performance improvement

## Breaking changes
[Yes/No — if yes, describe the impact and migration path]

## Related issues
Closes #[issue number]
```

### 10.3 Review Process

1. PR is assigned to 1-2 reviewers from the maintainers team
2. CI must pass (tests, lint, build)
3. At least 1 maintainer approval required
4. For detection rules: security team review required
5. For sensor code: platform-specific review required
6. Maintainer merges using squash-and-merge for small PRs, merge commit for large feature branches

### 10.4 Review Standards

Reviewers look for:
- **Correctness**: Does it do what it says?
- **Security**: Does it introduce any vulnerabilities?
- **Performance**: Does it meet the resource requirements from SYSTEM_ARCHITECTURE.md?
- **Consistency**: Does it follow coding standards?
- **Tests**: Are there adequate tests?
- **Documentation**: Is behavior documented?

Reviewers are expected to be constructive. "This should use X instead" is better than "Why did you use Y? That's wrong."

### 10.5 Getting Unstuck

If your PR has been waiting for review for more than 5 business days, ping the maintainers in the PR comments. We aim for first review within 3 business days for most PRs.

---

## 11. Security Vulnerability Reporting

**Do not open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities to: **security@r3trive.io**

Our PGP key for encrypted reports:
```
Key ID: 0x[PGP KEY ID]
Fingerprint: [FINGERPRINT]
Available at: https://r3trive.io/.well-known/security.txt
```

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure):
- We will acknowledge your report within 48 hours
- We aim to fix critical vulnerabilities within 7 days
- We will credit you in the security advisory (unless you prefer anonymity)
- We ask for 90 days before public disclosure to allow time for fix and deployment

---

## 12. Release Process

Releases are managed by maintainers. The process:

1. Create release branch: `release/v1.2.0`
2. Update `CHANGELOG.md` with all changes since last release
3. Update version in `internal/version/version.go`
4. Tag the release: `git tag v1.2.0 -s`
5. CI builds and signs release artifacts
6. GitHub release created with changelog notes
7. Docker image pushed to registry
8. Documentation site updated

### 12.1 Versioning

R3TRIVE follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking change to CLI, API, rule format, or plugin interface
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes, security patches, rule additions

### 12.2 Backport Policy

Security fixes are backported to the last 2 minor versions.

---

## 13. Recognition

All contributors are listed in `CONTRIBUTORS.md`. We follow the [All Contributors](https://allcontributors.org/) specification to recognize all types of contribution, not just code.

Notable contributions may be called out in:
- Release notes
- Project blog
- Annual security report

Thank you for helping make R3TRIVE better. Every bug report, rule contribution, and line of code matters.

---

*Questions? Ask in [GitHub Discussions](https://github.com/r3trive/r3trive/discussions) or join our community at [community.r3trive.io](https://community.r3trive.io).*
