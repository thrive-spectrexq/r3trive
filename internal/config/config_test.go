package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
		return
	}

	if cfg.LogLevel != "info" {
		t.Errorf("expected LogLevel 'info', got %s", cfg.LogLevel)
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("expected Storage.Driver 'sqlite', got %s", cfg.Storage.Driver)
	}
	if cfg.OutputFmt != "table" {
		t.Errorf("expected OutputFmt 'table', got %s", cfg.OutputFmt)
	}
	if cfg.Storage.BatchSize != 100 {
		t.Errorf("expected BatchSize 100, got %d", cfg.Storage.BatchSize)
	}
	if cfg.Sensor.RingBufferSize != 10000 {
		t.Errorf("expected RingBufferSize 10000, got %d", cfg.Sensor.RingBufferSize)
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Default() config failed validation: %v", err)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name: "invalid log level",
			modify: func(c *Config) {
				c.LogLevel = "verbose"
			},
			wantErr: true,
		},
		{
			name: "invalid storage driver",
			modify: func(c *Config) {
				c.Storage.Driver = "mysql"
			},
			wantErr: true,
		},
		{
			name: "invalid output format",
			modify: func(c *Config) {
				c.OutputFmt = "xml"
			},
			wantErr: true,
		},
		{
			name: "invalid batch size",
			modify: func(c *Config) {
				c.Storage.BatchSize = 0
			},
			wantErr: true,
		},
		{
			name: "invalid ring buffer size",
			modify: func(c *Config) {
				c.Sensor.RingBufferSize = 50
			},
			wantErr: true,
		},
		{
			name: "valid postgres driver",
			modify: func(c *Config) {
				c.Storage.Driver = "postgres"
				c.Storage.DSN = "postgres://localhost:5432/r3trive"
			},
			wantErr: false,
		},
		{
			name: "invalid postgres dsn format",
			modify: func(c *Config) {
				c.Storage.Driver = "postgres"
				c.Storage.DSN = "/tmp/local.db"
			},
			wantErr: true,
		},
		{
			name: "invalid tls pairing - cert only",
			modify: func(c *Config) {
				c.API.TLSCert = "/etc/ssl/cert.pem"
				c.API.TLSKey = ""
			},
			wantErr: true,
		},
		{
			name: "invalid tls pairing - key only",
			modify: func(c *Config) {
				c.API.TLSCert = ""
				c.API.TLSKey = "/etc/ssl/key.pem"
			},
			wantErr: true,
		},
		{
			name: "insecure non-loopback bind rejected by default",
			modify: func(c *Config) {
				c.API.Addr = "0.0.0.0:8080"
				c.API.APIKey = ""
				c.API.TLSCert = ""
				c.API.TLSKey = ""
				c.API.AllowInsecureBinding = false
			},
			wantErr: true,
		},
		{
			name: "insecure non-loopback bind allowed with flag",
			modify: func(c *Config) {
				c.API.Addr = "0.0.0.0:8080"
				c.API.APIKey = ""
				c.API.TLSCert = ""
				c.API.TLSKey = ""
				c.API.AllowInsecureBinding = true
			},
			wantErr: false,
		},
		{
			name: "non-loopback bind allowed with api_key",
			modify: func(c *Config) {
				c.API.Addr = "0.0.0.0:8080"
				c.API.APIKey = "secret-token"
			},
			wantErr: false,
		},
		{
			name: "non-loopback bind allowed with tls",
			modify: func(c *Config) {
				c.API.Addr = "0.0.0.0:8080"
				c.API.TLSCert = "/path/to/cert.pem"
				c.API.TLSKey = "/path/to/key.pem"
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSaveAndLoadFromFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	cfg := Default()
	cfg.LogLevel = "debug"
	cfg.OutputFmt = "json"
	cfg.Storage.Driver = "postgres"
	cfg.Storage.DSN = "postgres://user:pass@localhost:5432/r3trive"
	cfg.Storage.BatchSize = 250

	if err := cfg.SaveToFile(configPath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	loaded, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if loaded.LogLevel != "debug" || loaded.OutputFmt != "json" || loaded.Storage.Driver != "postgres" || loaded.Storage.BatchSize != 250 {
		t.Errorf("loaded config does not match saved config: %+v", loaded)
	}

	// Non-existent file
	if _, err := LoadFromFile(filepath.Join(tempDir, "missing.yaml")); err == nil {
		t.Error("expected error loading missing config file, got nil")
	}

	// Corrupt file
	corruptPath := filepath.Join(tempDir, "corrupt.yaml")
	if err := os.WriteFile(corruptPath, []byte(":: invalid yaml ::"), 0o600); err != nil {
		t.Fatalf("writing corrupt file: %v", err)
	}
	if _, err := LoadFromFile(corruptPath); err == nil {
		t.Error("expected error loading corrupt config file, got nil")
	}
}

func TestPathsNotEmpty(t *testing.T) {
	dataDir := defaultDataDir()
	if dataDir == "" {
		t.Error("defaultDataDir returned empty string")
	}

	cfgPath := DefaultConfigPath()
	if cfgPath == "" {
		t.Error("DefaultConfigPath returned empty string")
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("R3TRIVE_LOG_LEVEL", "debug")
	t.Setenv("R3TRIVE_OUTPUT_FORMAT", "ndjson")
	t.Setenv("R3TRIVE_STORAGE_DRIVER", "postgres")
	t.Setenv("R3TRIVE_STORAGE_DSN", "postgres://user:secret@localhost:5432/r3trive")
	t.Setenv("R3TRIVE_STORAGE_BATCH_SIZE", "500")
	t.Setenv("R3TRIVE_API_ADDR", "0.0.0.0:9090")
	t.Setenv("R3TRIVE_API_ALLOW_INSECURE_BINDING", "true")
	t.Setenv("R3TRIVE_TELEMETRY_ENABLED", "1")
	t.Setenv("R3TRIVE_AI_BACKEND", "ollama")

	cfg := Default()
	ApplyEnv(cfg)

	if cfg.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got %s", cfg.LogLevel)
	}
	if cfg.OutputFmt != "ndjson" {
		t.Errorf("expected OutputFmt 'ndjson', got %s", cfg.OutputFmt)
	}
	if cfg.Storage.Driver != "postgres" {
		t.Errorf("expected Storage.Driver 'postgres', got %s", cfg.Storage.Driver)
	}
	if cfg.Storage.DSN != "postgres://user:secret@localhost:5432/r3trive" {
		t.Errorf("expected Storage.DSN 'postgres://user:secret@localhost:5432/r3trive', got %s", cfg.Storage.DSN)
	}
	if cfg.Storage.BatchSize != 500 {
		t.Errorf("expected Storage.BatchSize 500, got %d", cfg.Storage.BatchSize)
	}
	if cfg.API.Addr != "0.0.0.0:9090" {
		t.Errorf("expected API.Addr '0.0.0.0:9090', got %s", cfg.API.Addr)
	}
	if !cfg.API.AllowInsecureBinding {
		t.Errorf("expected API.AllowInsecureBinding true, got false")
	}
	if !cfg.Telemetry.Enabled {
		t.Errorf("expected Telemetry.Enabled true, got false")
	}
	if cfg.AI.Backend != "ollama" {
		t.Errorf("expected AI.Backend 'ollama', got %s", cfg.AI.Backend)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed on env-overlaid config: %v", err)
	}
}

func TestProductionModeValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name: "production mode without api key fails",
			modify: func(c *Config) {
				c.Mode = "production"
				c.API.APIKey = ""
			},
			wantErr: true,
		},
		{
			name: "production mode with allow_insecure_binding fails",
			modify: func(c *Config) {
				c.Mode = "production"
				c.API.APIKey = "valid-secret-key"
				c.API.AllowInsecureBinding = true
			},
			wantErr: true,
		},
		{
			name: "production mode with wildcard cors fails",
			modify: func(c *Config) {
				c.Mode = "production"
				c.API.APIKey = "valid-secret-key"
				c.API.CORSOrigins = []string{"*"}
			},
			wantErr: true,
		},
		{
			name: "production mode non-loopback without tls fails",
			modify: func(c *Config) {
				c.Mode = "production"
				c.API.APIKey = "valid-secret-key"
				c.API.Addr = "192.168.1.100:8080"
				c.API.TLSCert = ""
				c.API.TLSKey = ""
			},
			wantErr: true,
		},
		{
			name: "production mode valid loopback passes",
			modify: func(c *Config) {
				c.Mode = "production"
				c.API.APIKey = "valid-secret-key"
				c.API.Addr = "127.0.0.1:8080"
				c.API.CORSOrigins = []string{"https://console.r3trive.io"}
			},
			wantErr: false,
		},
		{
			name: "production mode valid non-loopback with tls passes",
			modify: func(c *Config) {
				c.Mode = "production"
				c.API.APIKey = "valid-secret-key"
				c.API.Addr = "0.0.0.0:8443"
				c.API.TLSCert = "/etc/ssl/cert.pem"
				c.API.TLSKey = "/etc/ssl/key.pem"
				c.API.CORSOrigins = []string{"https://console.r3trive.io"}
			},
			wantErr: false,
		},
		{
			name: "invalid mode fails",
			modify: func(c *Config) {
				c.Mode = "staging-unknown"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestModeEnvOverlay(t *testing.T) {
	t.Setenv("R3TRIVE_MODE", "production")
	t.Setenv("R3TRIVE_API_KEY", "env-secret-key")

	cfg := Default()
	ApplyEnv(cfg)

	if cfg.Mode != "production" {
		t.Errorf("expected Mode 'production', got %s", cfg.Mode)
	}
	if cfg.API.APIKey != "env-secret-key" {
		t.Errorf("expected API.APIKey 'env-secret-key', got %s", cfg.API.APIKey)
	}
}

func TestMaskDSN(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "/var/lib/r3trive.db",
			want:  "/var/lib/r3trive.db",
		},
		{
			input: "postgres://admin:secret123@localhost:5432/r3trivedb?sslmode=disable",
			want:  "postgres://admin:****@localhost:5432/r3trivedb?sslmode=disable",
		},
		{
			input: "postgresql://user@localhost/db",
			want:  "postgresql://user@localhost/db",
		},
	}

	for _, tt := range tests {
		got := MaskDSN(tt.input)
		if got != tt.want {
			t.Errorf("MaskDSN(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLogEffective(t *testing.T) {
	cfg := Default()
	cfg.Storage.DSN = "postgres://operator:mypassword@localhost:5432/r3trive"
	cfg.API.APIKey = "super-secret"
	cfg.API.TLSCert = "/etc/cert.pem"
	cfg.API.TLSKey = "/etc/key.pem"

	// Must run without panic with nil or real logger
	cfg.LogEffective(nil)
	cfg.LogEffective(slog.Default())
}
