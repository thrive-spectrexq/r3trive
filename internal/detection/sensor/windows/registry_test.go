//go:build windows

package windows

import (
	"testing"
)

func TestNewRegistrySensor(t *testing.T) {
	s := NewRegistrySensor()
	if s == nil {
		t.Fatal("NewRegistrySensor() returned nil")
	}

	if s.Name() != RegistrySensorName {
		t.Errorf("expected name %s, got %s", RegistrySensorName, s.Name())
	}

	if s.Type() != "registry" {
		t.Errorf("expected type registry, got %s", s.Type())
	}

	platforms := s.Platform()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Errorf("unexpected platforms: %+v", platforms)
	}

	health := s.Health()
	if !health.Healthy {
		t.Error("expected initial health to be true")
	}

	// Test updateHealth
	s.updateHealth(nil)
	health = s.Health()
	if !health.Healthy || health.Status != "Running" {
		t.Errorf("unexpected health after updateHealth(nil): %+v", health)
	}

	if err := s.Stop(); err != nil {
		t.Errorf("expected clean Stop(), got %v", err)
	}
}
