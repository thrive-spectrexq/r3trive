// Package audit implements the security baseline assessment engine.
// It runs configurable security checks against the local host and
// reports findings with pass/fail/warn/skip status.
package audit

import (
	"fmt"
	"log/slog"
	"runtime"
)

// CheckStatus represents the outcome of a single audit check.
type CheckStatus string

// Check statuses.
const (
	StatusPass CheckStatus = "pass"
	StatusFail CheckStatus = "fail"
	StatusWarn CheckStatus = "warn"
	StatusSkip CheckStatus = "skip"
)

// CheckResult holds the result of a single audit check.
type CheckResult struct {
	Name     string      `json:"name"`
	Category string      `json:"category"`
	Status   CheckStatus `json:"status"`
	Detail   string      `json:"detail,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Results holds the aggregate results of an audit run.
type Results struct {
	Profile  string        `json:"profile"`
	Platform string        `json:"platform"`
	Total    int           `json:"total"`
	Passed   int           `json:"passed"`
	Failed   int           `json:"failed"`
	Warnings int           `json:"warnings"`
	Skipped  int           `json:"skipped"`
	Checks   []CheckResult `json:"checks"`
}

// Check is the interface for individual audit items.
type Check interface {
	// Name returns the check's display name.
	Name() string
	// Category returns the check's category (e.g., "Firewall", "Users").
	Category() string
	// Run executes the check and returns the result.
	Run() CheckResult
}

// Engine runs security audit checks against configurable profiles.
type Engine struct {
	checks []Check
}

// NewEngine creates a new audit engine with platform-appropriate checks.
func NewEngine() *Engine {
	e := &Engine{}

	e.checks = getPlatformChecks()
	if len(e.checks) == 0 {
		slog.Warn("no audit checks available for platform", "os", runtime.GOOS)
	}

	return e
}

// Run executes all checks matching the given profile.
func (e *Engine) Run(profile string) (*Results, error) {
	if len(e.checks) == 0 {
		return nil, fmt.Errorf("no audit checks available for %s", runtime.GOOS)
	}

	results := &Results{
		Profile:  profile,
		Platform: runtime.GOOS,
	}

	// For now all profiles run all checks; profiles will be filtered
	// when YAML profile definitions are added.
	for _, check := range e.checks {
		slog.Debug("running audit check", "name", check.Name(), "category", check.Category())

		result := check.Run()
		results.Checks = append(results.Checks, result)
		results.Total++

		switch result.Status {
		case StatusPass:
			results.Passed++
		case StatusFail:
			results.Failed++
		case StatusWarn:
			results.Warnings++
		case StatusSkip:
			results.Skipped++
		}
	}

	return results, nil
}
