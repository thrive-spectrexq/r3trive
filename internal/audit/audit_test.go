package audit

import (
	"testing"
)

type dummyCheck struct {
	status CheckStatus
}

func (d *dummyCheck) Name() string     { return "Dummy Check" }
func (d *dummyCheck) Category() string { return "Test" }
func (d *dummyCheck) Run() CheckResult {
	return CheckResult{
		Name:     d.Name(),
		Category: d.Category(),
		Status:   d.status,
		Detail:   "Test detail",
	}
}

func TestAuditEngineRun(t *testing.T) {
	e := &Engine{
		checks: []Check{
			&dummyCheck{status: StatusPass},
			&dummyCheck{status: StatusFail},
		},
	}

	results, err := e.Run("default")
	if err != nil {
		t.Fatalf("unexpected error running audit engine: %v", err)
	}

	if results.Total != 2 {
		t.Errorf("expected Total 2, got %d", results.Total)
	}
	if results.Passed != 1 {
		t.Errorf("expected Passed 1, got %d", results.Passed)
	}
	if results.Failed != 1 {
		t.Errorf("expected Failed 1, got %d", results.Failed)
	}
}
