//go:build !windows

package main

import (
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/config"
)

// initNativeSensors initializes platform-specific sensors for non-Windows platforms.
func initNativeSensors(cfg *config.Config) ([]sensor.Sensor, error) {
	// TODO: Implement eBPF (Linux) and ESF (macOS) sensors.
	return nil, nil
}
