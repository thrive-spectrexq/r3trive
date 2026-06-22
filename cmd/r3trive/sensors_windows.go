package main

import (
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/config"
)

// initNativeSensors initializes platform-specific sensors for Windows.
// This file is compiled only on Windows via the build tag.
func initNativeSensors(cfg *config.Config) ([]sensor.Sensor, error) {
	// TODO: Implement ETW-based sensors for Windows.
	// For now, return empty to fall back to mock sensors.
	return nil, nil
}
