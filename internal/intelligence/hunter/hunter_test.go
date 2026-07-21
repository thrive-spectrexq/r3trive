package hunter

import (
	"context"
	"testing"
)

func TestHunter(t *testing.T) {
	ctx := context.Background()
	h := New(nil)

	opts := HuntOptions{
		Technique: "T1003",
	}

	res, err := h.Hunt(ctx, opts)
	if err != nil {
		t.Fatalf("expected no error from Hunt, got %v", err)
	}

	if res == nil {
		t.Fatalf("expected non-nil HuntResult")
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
}
