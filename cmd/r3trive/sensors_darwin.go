//go:build darwin

package main

import (
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/macos"
)

// initNativeSensors initializes platform-specific sensors for macOS.
func initNativeSensors(cfg *config.Config) ([]sensor.Sensor, error) {
	var sensors []sensor.Sensor
	sensors = append(sensors, macos.NewProcessSensor())
	return sensors, nil
}
