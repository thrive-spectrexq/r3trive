package version

import (
	"strings"
	"testing"
)

func TestVersionInfo(t *testing.T) {
	short := Short()
	if short == "" {
		t.Error("Short() returned empty string")
	}

	info := Info()
	if !strings.Contains(info, "r3trive") {
		t.Errorf("Info() expected to contain 'r3trive', got %s", info)
	}
}
