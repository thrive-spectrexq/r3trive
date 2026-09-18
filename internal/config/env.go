package config

import (
	"os"
	"strconv"
	"strings"
)

// ApplyEnv overlays environment variables onto an existing Config.
// Environment variables take precedence over configuration files and defaults.
// Prefix convention is R3TRIVE_*.
func ApplyEnv(cfg *Config) {
	if cfg == nil {
		return
	}

	// General
	if val := os.Getenv("R3TRIVE_LOG_LEVEL"); val != "" {
		cfg.LogLevel = val
	}
	if val := os.Getenv("R3TRIVE_DATA_DIR"); val != "" {
		cfg.DataDir = val
	}
	if val := os.Getenv("R3TRIVE_OUTPUT_FORMAT"); val != "" {
		cfg.OutputFmt = val
	}

	// Monitor
	if val := os.Getenv("R3TRIVE_MONITOR_MIN_SEVERITY"); val != "" {
		cfg.Monitor.MinSeverity = val
	}
	if val, ok := parseEnvInt("R3TRIVE_MONITOR_POLL_INTERVAL_MS"); ok {
		cfg.Monitor.PollIntervalMs = val
	}

	// Storage
	if val := os.Getenv("R3TRIVE_STORAGE_DRIVER"); val != "" {
		cfg.Storage.Driver = val
	}
	if val := os.Getenv("R3TRIVE_STORAGE_DSN"); val != "" {
		cfg.Storage.DSN = val
	}
	if val, ok := parseEnvInt("R3TRIVE_STORAGE_BATCH_SIZE"); ok {
		cfg.Storage.BatchSize = val
	}
	if val, ok := parseEnvInt("R3TRIVE_STORAGE_FLUSH_INTERVAL_MS"); ok {
		cfg.Storage.FlushIntervalMs = val
	}
	if val, ok := parseEnvInt("R3TRIVE_STORAGE_RETENTION_DAYS"); ok {
		cfg.Storage.RetentionDays = val
	}

	// AI
	if val := os.Getenv("R3TRIVE_AI_BACKEND"); val != "" {
		cfg.AI.Backend = val
	}
	if val := os.Getenv("R3TRIVE_AI_ENDPOINT"); val != "" {
		cfg.AI.Endpoint = val
	}
	if val := os.Getenv("R3TRIVE_AI_MODEL"); val != "" {
		cfg.AI.Model = val
	}
	if val := os.Getenv("R3TRIVE_AI_API_KEY"); val != "" {
		cfg.AI.APIKey = val
	} else if cfg.AI.APIKey == "" {
		if val := os.Getenv("OPENAI_API_KEY"); val != "" {
			cfg.AI.APIKey = val
		}
	}

	// Telemetry
	if val, ok := parseEnvBool("R3TRIVE_TELEMETRY_ENABLED"); ok {
		cfg.Telemetry.Enabled = val
	}
	if val := os.Getenv("R3TRIVE_TELEMETRY_ENDPOINT"); val != "" {
		cfg.Telemetry.Endpoint = val
	}

	// Sensor
	if val := os.Getenv("R3TRIVE_SENSOR_MODE"); val != "" {
		cfg.Sensor.Mode = val
	}
	if val, ok := parseEnvInt("R3TRIVE_SENSOR_RING_BUFFER_SIZE"); ok {
		cfg.Sensor.RingBufferSize = val
	}

	// API
	if val := os.Getenv("R3TRIVE_API_ADDR"); val != "" {
		cfg.API.Addr = val
	}
	if val := os.Getenv("R3TRIVE_API_KEY"); val != "" {
		cfg.API.APIKey = val
	}
	if val := os.Getenv("R3TRIVE_API_TLS_CERT"); val != "" {
		cfg.API.TLSCert = val
	}
	if val := os.Getenv("R3TRIVE_API_TLS_KEY"); val != "" {
		cfg.API.TLSKey = val
	}
	if val, ok := parseEnvInt("R3TRIVE_API_RATE_LIMIT"); ok {
		cfg.API.RateLimit = val
	}
	if val, ok := parseEnvBool("R3TRIVE_API_ALLOW_INSECURE_BINDING"); ok {
		cfg.API.AllowInsecureBinding = val
	}
}

func parseEnvInt(key string) (int, bool) {
	val := os.Getenv(key)
	if val == "" {
		return 0, false
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseEnvBool(key string) (bool, bool) {
	val := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if val == "" {
		return false, false
	}
	switch val {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}
