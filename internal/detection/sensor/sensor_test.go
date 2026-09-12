package sensor

import (
	"testing"
)

func TestSensorTypes(t *testing.T) {
	if PlatformLinux != "linux" {
		t.Errorf("expected PlatformLinux to be 'linux', got %s", PlatformLinux)
	}
	if PlatformWindows != "windows" {
		t.Errorf("expected PlatformWindows to be 'windows', got %s", PlatformWindows)
	}
	if PlatformMacOS != "darwin" {
		t.Errorf("expected PlatformMacOS to be 'darwin', got %s", PlatformMacOS)
	}

	h := SensorHealth{
		Healthy:         true,
		Status:          "Active",
		EventsCollected: 42,
		ErrorCount:      0,
	}

	if !h.Healthy || h.EventsCollected != 42 {
		t.Errorf("unexpected SensorHealth fields: %+v", h)
	}
}
