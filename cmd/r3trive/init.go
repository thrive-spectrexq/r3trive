package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize R3TRIVE configuration and database",
		Long: `Creates the default configuration file and initializes the local
event database. Run this once before using R3TRIVE for the first time.`,
		RunE: runInit,
	}
}

func runInit(cmd *cobra.Command, args []string) error {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE Initialization")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// 1. Create default config
	cfgPath := config.DefaultConfigPath()
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Printf("  ✓ Config already exists: %s\n", cfgPath)
	} else {
		defaultCfg := config.Default()
		if err := defaultCfg.SaveToFile(cfgPath); err != nil {
			return fmt.Errorf("creating config: %w", err)
		}
		fmt.Printf("  ✓ Created config: %s\n", cfgPath)
	}

	// 2. Load config
	defaultCfg := config.Default()

	// 3. Initialize database
	fmt.Printf("  → Initializing database (%s)...\n", defaultCfg.Storage.Driver)

	var store storage.Store
	var err error

	switch defaultCfg.Storage.Driver {
	case "sqlite":
		store, err = sqlite.New(defaultCfg.Storage.DSN)
	default:
		return fmt.Errorf("unsupported storage driver: %s", defaultCfg.Storage.Driver)
	}

	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			slog.Error("closing database", "error", closeErr)
		}
	}()

	fmt.Printf("  ✓ Database initialized: %s\n", defaultCfg.Storage.DSN)

	// 4. Create data directories
	dirs := []string{
		defaultCfg.DataDir,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	fmt.Printf("  ✓ Data directory: %s\n", defaultCfg.DataDir)

	fmt.Println()
	fmt.Println("  R3TRIVE initialized successfully.")
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Println("    r3trive audit --quick    Run a quick security audit")
	fmt.Println("    r3trive monitor          Start continuous monitoring")
	fmt.Println("    r3trive config show      View current configuration")
	fmt.Println()

	return nil
}
