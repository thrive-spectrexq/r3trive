//go:build linux

package linux

import (
	"testing"
)

func TestLinuxProcessSensorMetadata(t *testing.T) {
	s := NewProcessSensor()
	if s.Name() != "linux_process_sensor" {
		t.Errorf("expected linux_process_sensor, got %s", s.Name())
	}
	if s.Type() != "process" {
		t.Errorf("expected process, got %s", s.Type())
	}
	health := s.Health()
	if !health.Healthy {
		t.Errorf("expected healthy sensor")
	}
}
