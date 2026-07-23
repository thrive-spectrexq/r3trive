//go:build linux

package main

import (
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/linux"
)

// initNativeSensors initializes platform-specific sensors for Linux.
func initNativeSensors(cfg *config.Config) ([]sensor.Sensor, error) {
	var sensors []sensor.Sensor
	sensors = append(sensors, linux.NewProcessSensor())
	return sensors, nil
}
