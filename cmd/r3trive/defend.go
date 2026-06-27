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
	"github.com/thrive-spectrexq/r3trive/internal/response"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

var (
	defendMode      string
	defendThreshold int
	defendDaemon    bool
)

func newDefendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "defend",
		Short: "Start automated response and containment",
		Long: `The defend command evaluates open incidents and automatically executes
containment actions such as process termination, network blocking, and
host isolation based on the configured mode and threshold.`,
		RunE: runDefend,
	}

	cmd.Flags().StringVar(&defendMode, "mode", "active", "response mode: active, passive (dry-run)")
	cmd.Flags().IntVar(&defendThreshold, "threshold", 80, "minimum risk score to trigger response")
	cmd.Flags().BoolVar(&defendDaemon, "daemon", false, "run continuously to poll for new incidents")

	return cmd
}

func runDefend(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE Automated Defense Engine")
	fmt.Printf(" Mode: %s | Threshold: %d+\n", defendMode, defendThreshold)
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// Initialize storage
	var store storage.Store
	var err error
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
	default:
		return fmt.Errorf("unsupported storage driver: %s", cfg.Storage.Driver)
	}

	// Initialize response engine
	dryRun := defendMode != "active"
	engine := response.New(dryRun)

	// Single execution or daemon loop
	if defendDaemon {
		slog.Info("starting defense daemon loop")
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if err := processIncidents(ctx, store, engine, defendThreshold); err != nil {
					slog.Error("error processing incidents", "error", err)
				}
			}
		}
	} else {
		// Run once
		if err := processIncidents(ctx, store, engine, defendThreshold); err != nil {
			return fmt.Errorf("processing incidents: %w", err)
		}
		fmt.Println("\nDefense evaluation complete.")
	}

	return nil
}

func processIncidents(ctx context.Context, store storage.Store, engine *response.Engine, threshold int) error {
	incidents, err := store.QueryIncidents(ctx, []event.IncidentStatus{event.IncidentStatusOpen, event.IncidentStatusInvestigating})
	if err != nil {
		return fmt.Errorf("querying incidents: %w", err)
	}

	for _, inc := range incidents {
		if inc.RiskScore < threshold {
			continue
		}

		slog.Info("evaluating incident for automated response", "incident_id", inc.ID, "risk_score", inc.RiskScore)

		results, err := engine.RespondToIncident(ctx, inc, threshold)
		if err != nil {
			slog.Error("failed to respond to incident", "incident_id", inc.ID, "error", err)
			continue
		}

		if len(results) > 0 {
			allSuccess := true
			for _, r := range results {
				if !r.Success {
					allSuccess = false
				}
			}

			// Update incident status
			newStatus := event.IncidentStatusContained
			if !allSuccess {
				slog.Warn("partial failure during containment, marking as investigating", "incident_id", inc.ID)
				newStatus = event.IncidentStatusInvestigating
			}

			// In a dry run, we don't actually change the state in DB to avoid silencing the incident
			if defendMode == "active" {
				if err := store.UpdateIncidentStatus(ctx, inc.ID, newStatus); err != nil {
					slog.Error("failed to update incident status", "incident_id", inc.ID, "error", err)
				} else {
					slog.Info("incident contained", "incident_id", inc.ID)
				}
			}
		}
	}

	return nil
}
