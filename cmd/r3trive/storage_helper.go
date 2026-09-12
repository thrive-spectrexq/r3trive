package main

import (
	"fmt"
	"path/filepath"

	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/storage/postgres"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
)

// newStoreFromConfig initializes the configured storage backend (sqlite or postgres).
func newStoreFromConfig(cfg *config.Config) (storage.Store, error) {
	if cfg == nil {
		return sqlite.New("r3trive.db")
	}

	dsn := cfg.Storage.DSN
	if dsn == "" {
		if cfg.DataDir != "" {
			dsn = filepath.Join(cfg.DataDir, "r3trive.db")
		} else {
			dsn = "r3trive.db"
		}
	}

	switch cfg.Storage.Driver {
	case "postgres":
		return postgres.New(dsn)
	case "sqlite", "":
		return sqlite.New(dsn)
	default:
		return nil, fmt.Errorf("unsupported storage driver: %s", cfg.Storage.Driver)
	}
}
