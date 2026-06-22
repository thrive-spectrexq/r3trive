package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/config"
	"github.com/thrive-spectrexq/r3trive/internal/correlation"
	"github.com/thrive-spectrexq/r3trive/internal/detection/pipeline"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor/mock"
	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/internal/output"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

var (
	monitorLevel  string
	monitorDaemon bool
	monitorDev    bool
)

func newMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Start continuous endpoint monitoring",
		Long: `Continuously monitors process creation, network activity, file
modifications, registry changes, and service events. Events are
analyzed in real-time against behavioral detection rules.`,
		RunE: runMonitor,
	}

	cmd.Flags().StringVar(&monitorLevel, "level", "", "minimum severity level: low, medium, high, critical")
	cmd.Flags().BoolVar(&monitorDaemon, "daemon", false, "run as background daemon")
	cmd.Flags().BoolVar(&monitorDev, "dev", false, "development mode (verbose logging, mock sensors)")

	return cmd
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Override settings for dev mode
	if monitorDev {
		cfg.Sensor.Mode = "mock"
		cfg.LogLevel = "debug"
		setupLogging("debug")
	}

	if monitorLevel != "" {
		cfg.Monitor.MinSeverity = monitorLevel
	}

	// Print banner
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE Endpoint Monitor")
	fmt.Printf(" Mode: %s | Severity: %s+\n", cfg.Sensor.Mode, cfg.Monitor.MinSeverity)
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop monitoring")
	fmt.Println()

	// Initialize sensors
	sensors, err := initSensors(cfg)
	if err != nil {
		return fmt.Errorf("initializing sensors: %w", err)
	}

	// Initialize storage
	var store storage.Store
	switch cfg.Storage.Driver {
	case "sqlite":
		store, err = sqlite.New(cfg.Storage.DSN)
		if err != nil {
			return fmt.Errorf("initializing storage: %w", err)
		}
		defer func() {
			if closeErr := store.Close(); closeErr != nil {
				slog.Error("closing storage", "error", closeErr)
			}
		}()
	}

	// Initialize YARA Scanner
	yaraScanner := yara.NewMockScanner()
	_ = yaraScanner.LoadRules("rules/yara")

	// Build event pipeline
	pipe := pipeline.New(pipeline.Config{
		Sensors:        sensors,
		Store:          store,
		YaraScanner:    yaraScanner,
		RingBufferSize: cfg.Sensor.RingBufferSize,
		BatchSize:      cfg.Storage.BatchSize,
		FlushInterval:  time.Duration(cfg.Storage.FlushIntervalMs) * time.Millisecond,
	})

	// Setup correlation engine
	corrEngine := correlation.New()
	rules, err := correlation.LoadRulesFromDirectory("rules/behavioral")
	if err == nil {
		corrEngine.LoadRules(rules)
	} else {
		slog.Warn("could not load correlation rules", "error", err)
	}

	// Setup output
	outFmt, _ := output.ParseFormat(cfg.OutputFmt)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	// Event display callback
	minSeverity := parseSeverity(cfg.Monitor.MinSeverity)
	pipe.OnEvent(func(evt event.Event) {
		// Evaluate event against rules
		alerts := corrEngine.Evaluate(ctx, evt)
		for _, alert := range alerts {
			fmt.Printf("\n[!] ALERT TRIGGERED: %s (Rule: %s, Sev: %s, Score: %d)\n", 
				alert.Message, alert.RuleName, alert.Severity, alert.RiskScore)
		}

		if severityRank(evt.Severity) < severityRank(minSeverity) {
			return
		}

		switch outFmt {
		case output.FormatJSON, output.FormatNDJSON:
			if err := formatter.WriteObject(evt); err != nil {
				slog.Error("writing event", "error", err)
			}
		case output.FormatQuiet:
			// no output
		default:
			printEventLine(evt)
		}
	})

	// Start pipeline
	slog.Info("starting event pipeline",
		"sensors", len(sensors),
		"mode", cfg.Sensor.Mode,
		"ring_buffer", cfg.Sensor.RingBufferSize,
	)

	if err := pipe.Start(ctx); err != nil {
		return fmt.Errorf("running pipeline: %w", err)
	}

	return nil
}

func initSensors(cfg *config.Config) ([]sensor.Sensor, error) {
	var sensors []sensor.Sensor

	if cfg.Sensor.Mode == "mock" {
		slog.Info("using mock sensors")
		sensors = append(sensors, mock.NewProcessSensor())
		sensors = append(sensors, mock.NewNetworkSensor())
		return sensors, nil
	}

	// Native sensors will be added per-platform via build tags
	nativeSensors, err := initNativeSensors(cfg)
	if err != nil {
		return nil, err
	}
	sensors = append(sensors, nativeSensors...)

	if len(sensors) == 0 {
		slog.Warn("no native sensors available, falling back to mock")
		sensors = append(sensors, mock.NewProcessSensor())
		sensors = append(sensors, mock.NewNetworkSensor())
	}

	return sensors, nil
}

func printEventLine(evt event.Event) {
	ts := evt.Timestamp.Format("15:04:05")

	var detail string
	switch {
	case evt.Data.Process != nil:
		p := evt.Data.Process
		detail = fmt.Sprintf("PID:%d %s → %s", p.PID, p.Name, p.CmdLine)
		if len(detail) > 80 {
			detail = detail[:77] + "..."
		}
	case evt.Data.Network != nil:
		n := evt.Data.Network
		detail = fmt.Sprintf("%s %s:%d → %s:%d (%s)",
			n.Protocol, n.SrcIP, n.SrcPort, n.DstIP, n.DstPort, n.ProcessName)
	case evt.Data.File != nil:
		detail = fmt.Sprintf("%s", evt.Data.File.Path)
	default:
		detail = string(evt.Type)
	}

	severityIcon := severityIcon(evt.Severity)
	fmt.Printf("  %s %s [%s] %s\n", ts, severityIcon, evt.Type, detail)
}

func severityIcon(s event.Severity) string {
	switch s {
	case event.SeverityLow:
		return "○"
	case event.SeverityMedium:
		return "●"
	case event.SeverityHigh:
		return "▲"
	case event.SeverityCritical:
		return "◆"
	default:
		return "·"
	}
}

func parseSeverity(s string) event.Severity {
	switch s {
	case "low":
		return event.SeverityLow
	case "medium":
		return event.SeverityMedium
	case "high":
		return event.SeverityHigh
	case "critical":
		return event.SeverityCritical
	default:
		return event.SeverityLow
	}
}

func severityRank(s event.Severity) int {
	switch s {
	case event.SeverityLow:
		return 0
	case event.SeverityMedium:
		return 1
	case event.SeverityHigh:
		return 2
	case event.SeverityCritical:
		return 3
	default:
		return -1
	}
}
