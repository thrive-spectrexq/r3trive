// R3TRIVE — Enterprise-grade endpoint detection, threat hunting, and automated defense.
//
// Usage:
//
//	r3trive [command] [flags]
package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/config"
)

var (
	// Global flags
	cfgFile   string
	outputFmt string
	logLevel  string
	quiet     bool

	// Global config (loaded in PersistentPreRun)
	cfg *config.Config
)

func main() {
	rootCmd := newRootCmd()

	// Register subcommands
	rootCmd.AddCommand(
		newVersionCmd(),
		newInitCmd(),
		newMonitorCmd(),
		newAuditCmd(),
		newConfigCmd(),
		newAskCmd(),
		newGenerateRuleCmd(),
		newDefendCmd(),
		newExplainCmd(),
		newSummarizeCmd(),
		newHuntCmd(),
		newInvestigateCmd(),
		newYaraCmd(),
		newSigmaCmd(),
		newAttackChainCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "r3trive",
		Short: "Enterprise endpoint detection, threat hunting, and automated defense",
		Long: `
  _____  ____ _______ _____  _______      ________ 
 |  __ \|___ \__   __|  __ \|_   _\ \    / /  ____|
 | |__) | __) | | |  | |__) | | |  \ \  / /| |__   
 |  _  / |__ <  | |  |  _  /  | |   \ \/ / |  __|  
 | | \ \ ___) | | |  | | \ \ _| |_   \  /  | |____ 
 |_|  \_\____/  |_|  |_|  \_\_____|   \/   |______|

R3TRIVE is a cross-platform cybersecurity platform built for defensive
security operations at scale. It combines behavioral endpoint detection,
AI-assisted investigation, automated response, and threat hunting into
a single terminal-first tool.

Documentation: https://docs.r3trive.io`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip config loading for init and version commands
			cmdName := cmd.Name()
			if cmdName == "init" || cmdName == "version" {
				return nil
			}

			return loadConfig()
		},
	}

	// Global flags
	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default: auto-detected)")
	cmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "output format: table, json, ndjson, csv, quiet")
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "log level: trace, debug, info, warn, error")
	cmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress all output except errors")

	return cmd
}

// loadConfig loads configuration from file, env vars, and flags.
func loadConfig() error {
	var err error

	if cfgFile != "" {
		cfg, err = config.LoadFromFile(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
	} else {
		// Try default config path
		defaultPath := config.DefaultConfigPath()
		if _, statErr := os.Stat(defaultPath); statErr == nil {
			cfg, err = config.LoadFromFile(defaultPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
		} else {
			// No config file found, use defaults
			cfg = config.Default()
		}
	}

	// Override with flags
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}
	if outputFmt != "" && outputFmt != "table" {
		cfg.OutputFmt = outputFmt
	}
	if quiet {
		cfg.OutputFmt = "quiet"
	}

	// Setup logging
	setupLogging(cfg.LogLevel)

	return nil
}

// setupLogging configures the global slog logger.
func setupLogging(level string) {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "trace", "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
	})
	slog.SetDefault(slog.New(handler))
}
