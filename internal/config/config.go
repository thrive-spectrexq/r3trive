// Package config manages R3TRIVE configuration loading, validation, and defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config holds all R3TRIVE configuration.
type Config struct {
	// General settings
	LogLevel  string `yaml:"log_level" json:"log_level"`
	DataDir   string `yaml:"data_dir" json:"data_dir"`
	OutputFmt string `yaml:"output_format" json:"output_format"`

	// Monitoring settings
	Monitor MonitorConfig `yaml:"monitor" json:"monitor"`

	// Storage settings
	Storage StorageConfig `yaml:"storage" json:"storage"`

	// AI settings
	AI AIConfig `yaml:"ai" json:"ai"`

	// Telemetry settings
	Telemetry TelemetryConfig `yaml:"telemetry" json:"telemetry"`

	// Sensor settings
	Sensor SensorConfig `yaml:"sensor" json:"sensor"`
}

// MonitorConfig holds monitoring-specific configuration.
type MonitorConfig struct {
	// MinSeverity filters events below this severity level.
	MinSeverity string `yaml:"min_severity" json:"min_severity"`
	// PollIntervalMs is the sensor polling interval in milliseconds.
	PollIntervalMs int `yaml:"poll_interval_ms" json:"poll_interval_ms"`
	// EnabledSensors lists which sensors to activate.
	EnabledSensors []string `yaml:"enabled_sensors" json:"enabled_sensors"`
}

// StorageConfig holds storage-specific configuration.
type StorageConfig struct {
	// Driver is the storage backend ("sqlite" or "postgres").
	Driver string `yaml:"driver" json:"driver"`
	// DSN is the data source name / connection string.
	DSN string `yaml:"dsn" json:"dsn"`
	// BatchSize is the number of events to batch before flushing.
	BatchSize int `yaml:"batch_size" json:"batch_size"`
	// FlushIntervalMs is the max time between flushes in milliseconds.
	FlushIntervalMs int `yaml:"flush_interval_ms" json:"flush_interval_ms"`
	// RetentionDays is how long to keep events.
	RetentionDays int `yaml:"retention_days" json:"retention_days"`
}

// AIConfig holds AI backend configuration.
type AIConfig struct {
	// Backend is the AI provider ("ollama", "openai", "none").
	Backend string `yaml:"backend" json:"backend"`
	// Endpoint is the API endpoint URL.
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	// Model is the model name to use.
	Model string `yaml:"model" json:"model"`
}

// TelemetryConfig holds OpenTelemetry configuration.
type TelemetryConfig struct {
	// Enabled controls whether telemetry is active.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Endpoint is the OTLP exporter endpoint.
	Endpoint string `yaml:"endpoint" json:"endpoint"`
}

// SensorConfig holds sensor-specific configuration.
type SensorConfig struct {
	// Mode is the sensor mode ("native", "mock").
	Mode string `yaml:"mode" json:"mode"`
	// RingBufferSize is the in-memory event buffer capacity.
	RingBufferSize int `yaml:"ring_buffer_size" json:"ring_buffer_size"`
}

// Default returns a Config populated with sensible defaults.
func Default() *Config {
	dataDir := defaultDataDir()
	dbPath := filepath.Join(dataDir, "r3trive.db")

	return &Config{
		LogLevel:  "info",
		DataDir:   dataDir,
		OutputFmt: "table",
		Monitor: MonitorConfig{
			MinSeverity:    "low",
			PollIntervalMs: 1000,
			EnabledSensors: []string{"process", "network"},
		},
		Storage: StorageConfig{
			Driver:          "sqlite",
			DSN:             dbPath,
			BatchSize:       100,
			FlushIntervalMs: 1000,
			RetentionDays:   30,
		},
		AI: AIConfig{
			Backend:  "none",
			Endpoint: "http://localhost:11434",
			Model:    "llama3",
		},
		Telemetry: TelemetryConfig{
			Enabled:  false,
			Endpoint: "localhost:4317",
		},
		Sensor: SensorConfig{
			Mode:           "native",
			RingBufferSize: 10000,
		},
	}
}

// LoadFromFile reads a YAML configuration file and merges it with defaults.
func LoadFromFile(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validating: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	validLogLevels := map[string]bool{
		"trace": true, "debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log_level %q, must be one of: trace, debug, info, warn, error", c.LogLevel)
	}

	validDrivers := map[string]bool{"sqlite": true, "postgres": true}
	if !validDrivers[c.Storage.Driver] {
		return fmt.Errorf("invalid storage driver %q, must be sqlite or postgres", c.Storage.Driver)
	}

	validOutputs := map[string]bool{
		"table": true, "json": true, "ndjson": true, "csv": true, "quiet": true,
	}
	if !validOutputs[c.OutputFmt] {
		return fmt.Errorf("invalid output_format %q", c.OutputFmt)
	}

	if c.Storage.BatchSize < 1 {
		return fmt.Errorf("storage.batch_size must be >= 1, got %d", c.Storage.BatchSize)
	}

	if c.Sensor.RingBufferSize < 100 {
		return fmt.Errorf("sensor.ring_buffer_size must be >= 100, got %d", c.Sensor.RingBufferSize)
	}

	return nil
}

// SaveToFile writes the configuration to a YAML file.
func (c *Config) SaveToFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("config: creating directory %s: %w", dir, err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshaling: %w", err)
	}

	header := []byte("# R3TRIVE Configuration\n# See documentation at https://docs.r3trive.io\n\n")
	data = append(header, data...)

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("config: writing %s: %w", path, err)
	}

	return nil
}

// defaultDataDir returns the platform-appropriate data directory.
func defaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		return filepath.Join(appData, "r3trive")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "r3trive")
	default:
		// XDG-compliant
		xdgData := os.Getenv("XDG_DATA_HOME")
		if xdgData == "" {
			home, _ := os.UserHomeDir()
			xdgData = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(xdgData, "r3trive")
	}
}

// DefaultConfigPath returns the platform-appropriate config file path.
func DefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		return filepath.Join(appData, "r3trive", "config.yaml")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "r3trive", "config.yaml")
	default:
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			home, _ := os.UserHomeDir()
			xdgConfig = filepath.Join(home, ".config")
		}
		return filepath.Join(xdgConfig, "r3trive", "config.yaml")
	}
}
