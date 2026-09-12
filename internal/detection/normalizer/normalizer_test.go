package normalizer

import (
	"runtime"
	"testing"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestNormalizer_Normalize(t *testing.T) {
	n := New()

	evt := event.Event{
		ID:   "evt-norm-1",
		Type: event.ProcessCreate,
		Host: event.HostInfo{
			Hostname: "box1",
		},
	}

	norm := n.Normalize(evt)

	if norm.Host.OS != runtime.GOOS {
		t.Errorf("expected OS %s, got %s", runtime.GOOS, norm.Host.OS)
	}
	if norm.Host.Arch != runtime.GOARCH {
		t.Errorf("expected Arch %s, got %s", runtime.GOARCH, norm.Host.Arch)
	}

	// Should preserve already populated fields
	prepopulated := event.Event{
		ID: "evt-norm-2",
		Host: event.HostInfo{
			OS:   "freebsd",
			Arch: "arm",
		},
	}
	normPre := n.Normalize(prepopulated)
	if normPre.Host.OS != "freebsd" || normPre.Host.Arch != "arm" {
		t.Errorf("prepopulated host fields were overwritten: %+v", normPre.Host)
	}
}
