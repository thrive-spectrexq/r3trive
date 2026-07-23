//go:build !windows && !linux && !darwin

package main

import (
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
)

// initNativeSensors initializes platform-specific sensors for unsupported platforms.
func initNativeSensors(cfg *config.Config) ([]sensor.Sensor, error) {
	return nil, nil
}
