package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/output"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage R3TRIVE configuration",
	}

	cmd.AddCommand(newConfigShowCmd())
	cmd.AddCommand(newConfigValidateCmd())

	return cmd
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Display current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			outFmt, _ := output.ParseFormat(cfg.OutputFmt)
			formatter := output.NewFormatter(os.Stdout, outFmt)

			switch outFmt {
			case output.FormatJSON, output.FormatNDJSON:
				return formatter.WriteObject(cfg)
			default:
				fmt.Println("═══════════════════════════════════════════")
				fmt.Println(" R3TRIVE Configuration")
				fmt.Println("═══════════════════════════════════════════")
				fmt.Println()

				headers := []string{"Setting", "Value"}
				rows := [][]string{
					{"log_level", cfg.LogLevel},
					{"data_dir", cfg.DataDir},
					{"output_format", cfg.OutputFmt},
					{"storage.driver", cfg.Storage.Driver},
					{"storage.dsn", cfg.Storage.DSN},
					{"storage.batch_size", fmt.Sprintf("%d", cfg.Storage.BatchSize)},
					{"storage.retention_days", fmt.Sprintf("%d", cfg.Storage.RetentionDays)},
					{"monitor.min_severity", cfg.Monitor.MinSeverity},
					{"monitor.poll_interval_ms", fmt.Sprintf("%d", cfg.Monitor.PollIntervalMs)},
					{"sensor.mode", cfg.Sensor.Mode},
					{"sensor.ring_buffer_size", fmt.Sprintf("%d", cfg.Sensor.RingBufferSize)},
					{"ai.backend", cfg.AI.Backend},
					{"telemetry.enabled", fmt.Sprintf("%v", cfg.Telemetry.Enabled)},
				}
				return formatter.WriteTable(headers, rows)
			}
		},
	}
}

func newConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := cfgFile
			if path == "" {
				path = config.DefaultConfigPath()
			}

			_, err := config.LoadFromFile(path)
			if err != nil {
				fmt.Printf("  ✗ Configuration invalid: %v\n", err)
				return err
			}

			fmt.Printf("  ✓ Configuration valid: %s\n", path)
			return nil
		},
	}
}
