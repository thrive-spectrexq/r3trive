package config

import (
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
