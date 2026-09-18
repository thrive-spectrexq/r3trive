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
		newServeCmd(),
		newPluginsCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		exitCode, category := classifyError(err)
		fmt.Fprintf(os.Stderr, "\n[%s] %v\n", category, err)
		os.Exit(exitCode)
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

Maintained by https://github.com/thrive-spectrexq

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

// loadConfig loads configuration following the precedence:
// CLI Flags > Environment Variables (R3TRIVE_*) > Config File > Defaults.
func loadConfig() error {
	var err error

	if cfgFile != "" {
		cfg, err = config.LoadFromFile(cfgFile)
		if err != nil {
			return NewConfigError(fmt.Sprintf("loading config: %v", err))
		}
	} else {
		// Try default config path
		defaultPath := config.DefaultConfigPath()
		if _, statErr := os.Stat(defaultPath); statErr == nil {
			cfg, err = config.LoadFromFile(defaultPath)
			if err != nil {
				return NewConfigError(fmt.Sprintf("loading config: %v", err))
			}
		} else {
			// No config file found, use defaults
			cfg = config.Default()
		}
	}

	// 1. Overlay environment variables (R3TRIVE_*)
	config.ApplyEnv(cfg)

	// 2. Override with CLI flags (highest precedence)
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}
	if outputFmt != "" && outputFmt != "table" {
		cfg.OutputFmt = outputFmt
	}
	if quiet {
		cfg.OutputFmt = "quiet"
	}

	// 3. Re-validate final merged config
	if err := cfg.Validate(); err != nil {
		return NewConfigError(fmt.Sprintf("validating merged configuration: %v", err))
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
