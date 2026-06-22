package main

import (
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/windows"
)

// initNativeSensors initializes platform-specific sensors for Windows.
// This file is compiled only on Windows via the build tag.
func initNativeSensors(cfg *config.Config) ([]sensor.Sensor, error) {
	var sensors []sensor.Sensor
	
	// Add ETW sensors
	sensors = append(sensors, windows.NewProcessSensor())
	sensors = append(sensors, windows.NewNetworkSensor())
	sensors = append(sensors, windows.NewFileSensor())
	
	return sensors, nil
}
