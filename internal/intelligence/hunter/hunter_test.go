package hunter

import (
	"context"
	"testing"
)

func TestHunterWithTargetProcesses(t *testing.T) {
	ctx := context.Background()
	h := New(nil)

	// 1. Hunt with simulated suspicious process
	opts := HuntOptions{
		Technique: "T1003",
		Processes: []ProcessInfo{
			{PID: 1337, Name: "mimikatz.exe", CmdLine: "mimikatz.exe sekurlsa::logonpasswords"},
			{PID: 400, Name: "explorer.exe", CmdLine: "explorer.exe"},
		},
	}

	res, err := h.Hunt(ctx, opts)
	if err != nil {
		t.Fatalf("expected no error from Hunt, got %v", err)
	}

	if res == nil {
		t.Fatalf("expected non-nil HuntResult")
		return
	}

	if len(res.Findings) == 0 {
		t.Errorf("expected findings for technique T1003, got 0")
	}

	found := false
	for _, f := range res.Findings {
		if f.Technique == "T1003.001" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected finding with T1003.001 technique")
	}

	// 2. Hunt with benign processes only
	benignOpts := HuntOptions{
		Technique: "T1003",
		Processes: []ProcessInfo{
			{PID: 400, Name: "explorer.exe"},
			{PID: 500, Name: "svchost.exe"},
		},
	}

	benignRes, err := h.Hunt(ctx, benignOpts)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(benignRes.Findings) != 0 {
		t.Errorf("expected 0 findings for clean processes, got %d", len(benignRes.Findings))
	}
}

func TestHunterLiveProcesses(t *testing.T) {
	ctx := context.Background()
	h := New(nil)

	// Live system hunt should scan and not error
	res, err := h.Hunt(ctx, HuntOptions{})
	if err != nil {
		t.Fatalf("expected no error on live hunt, got %v", err)
	}
	if res == nil {
		t.Fatalf("expected non-nil HuntResult")
		return
	}
	if res.TotalScanned == 0 {
		t.Logf("warning: TotalScanned was 0 on this test environment")
	}
}
