package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/ai"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
)

func newAskCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ask [question]",
		Short: "Ask the AI analyst a security question",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if cfg.AI.Backend == "none" || cfg.AI.Backend == "" {
				return fmt.Errorf("AI backend is disabled in config. Run with --config pointing to a valid config")
			}

			aiCmds, err := ai.NewCommands(cfg.AI)
			if err != nil {
				return fmt.Errorf("failed to init AI: %w", err)
			}

			question := strings.Join(args, " ")
			fmt.Printf("🤔 Asking %s (Model: %s)...\n", cfg.AI.Backend, cfg.AI.Model)

			resp, err := aiCmds.Ask(ctx, question)
			if err != nil {
				return err
			}

			fmt.Println("\n🤖 AI Analyst Response:")
			fmt.Println("--------------------------------------------------")
			fmt.Println(resp)
			fmt.Println("--------------------------------------------------")
			return nil
		},
	}
}

func newGenerateRuleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate-rule [scenario]",
		Short: "Ask the AI to generate a correlation rule from a description",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if cfg.AI.Backend == "none" || cfg.AI.Backend == "" {
				return fmt.Errorf("AI backend is disabled in config. Run with --config pointing to a valid config")
			}

			aiCmds, err := ai.NewCommands(cfg.AI)
			if err != nil {
				return fmt.Errorf("failed to init AI: %w", err)
			}

			scenario := strings.Join(args, " ")
			fmt.Printf("🛠️ Generating rule using %s (Model: %s)...\n", cfg.AI.Backend, cfg.AI.Model)

			resp, err := aiCmds.GenerateRule(ctx, scenario)
			if err != nil {
				return err
			}

			fmt.Println("\n📜 Generated YAML Rule:")
			fmt.Println("--------------------------------------------------")
			fmt.Println(resp)
			fmt.Println("--------------------------------------------------")
			return nil
		},
	}
}

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain [id]",
		Short: "Ask the AI to explain a specific incident or event",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if cfg.AI.Backend == "none" || cfg.AI.Backend == "" {
				return fmt.Errorf("AI backend is disabled in config. Run with --config pointing to a valid config")
			}

			store, err := sqlite.New(cfg.Storage.DSN)
			if err != nil {
				return fmt.Errorf("failed to init storage: %w", err)
			}
			defer store.Close()

			aiCmds, err := ai.NewCommands(cfg.AI)
			if err != nil {
				return fmt.Errorf("failed to init AI: %w", err)
			}

			id := args[0]
			fmt.Printf("🔍 Extracting context for %s...\n", id)

			var resp string
			if strings.HasPrefix(id, "INC-") {
				inc, err := store.GetIncident(ctx, id)
				if err != nil {
					return fmt.Errorf("failed to fetch incident: %w", err)
				}
				fmt.Printf("🤖 Explaining Incident %s (Model: %s)...\n", id, cfg.AI.Model)
				resp, err = aiCmds.ExplainIncident(ctx, inc)
				if err != nil {
					return err
				}
			} else {
				evt, err := store.GetEvent(ctx, id)
				if err != nil {
					return fmt.Errorf("failed to fetch event: %w", err)
				}
				fmt.Printf("🤖 Explaining Event %s (Model: %s)...\n", id, cfg.AI.Model)
				resp, err = aiCmds.ExplainEvent(ctx, evt)
				if err != nil {
					return err
				}
			}

			fmt.Println("\n🤖 AI Analyst Response:")
			fmt.Println("--------------------------------------------------")
			fmt.Println(resp)
			fmt.Println("--------------------------------------------------")
			return nil
		},
	}
}

func newSummarizeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "summarize [timeframe]",
		Short: "Ask the AI to summarize recent activity (e.g. '1h', '24h')",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if cfg.AI.Backend == "none" || cfg.AI.Backend == "" {
				return fmt.Errorf("AI backend is disabled in config. Run with --config pointing to a valid config")
			}

			duration, err := time.ParseDuration(args[0])
			if err != nil {
				return fmt.Errorf("invalid timeframe format (use e.g. 1h, 30m): %w", err)
			}

			store, err := sqlite.New(cfg.Storage.DSN)
			if err != nil {
				return fmt.Errorf("failed to init storage: %w", err)
			}
			defer store.Close()

			aiCmds, err := ai.NewCommands(cfg.AI)
			if err != nil {
				return fmt.Errorf("failed to init AI: %w", err)
			}

			fmt.Printf("📊 Fetching activity for the last %s...\n", args[0])
			since := time.Now().Add(-duration)

			events, err := store.QueryEvents(ctx, storage.EventQuery{
				Since: since,
				Limit: 200,
			})
			if err != nil {
				return fmt.Errorf("failed to query events: %w", err)
			}

			fmt.Printf("🤖 Summarizing %d events (Model: %s)...\n", len(events), cfg.AI.Model)
			resp, err := aiCmds.Summarize(ctx, events)
			if err != nil {
				return err
			}

			fmt.Println("\n🤖 AI Summary:")
			fmt.Println("--------------------------------------------------")
			fmt.Println(resp)
			fmt.Println("--------------------------------------------------")
			return nil
		},
	}
}

func newAttackChainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attack-chain [incident_id]",
		Short: "Reconstruct multi-stage attack chain for an incident",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			incidentID := args[0]

			store, err := sqlite.New(cfg.Storage.DSN)
			if err != nil {
				return fmt.Errorf("failed to init storage: %w", err)
			}
			defer store.Close()

			inc, err := store.GetIncident(ctx, incidentID)
			if err != nil {
				return fmt.Errorf("failed to fetch incident %s: %w", incidentID, err)
			}

			fmt.Println("═══════════════════════════════════════════")
			fmt.Println(" R3TRIVE Attack Chain Reconstruction")
			fmt.Printf(" Incident ID: %s | Severity: %s\n", inc.ID, inc.Severity)
			fmt.Println("═══════════════════════════════════════════")
			fmt.Println()

			if len(inc.Alerts) == 0 {
				fmt.Println("No correlated alerts attached to this incident.")
				return nil
			}

			fmt.Println("Attack Execution Flow:")
			for i, alert := range inc.Alerts {
				stage := "Initial Access"
				if alert.ATTACKTactic != "" {
					stage = alert.ATTACKTactic
				}
				tech := alert.ATTACKTechnique
				if tech == "" {
					tech = "T1059"
				}

				fmt.Printf("  Step %d: [%s] %s\n", i+1, stage, alert.RuleName)
				fmt.Printf("          Technique: %s | Risk Score: %d\n", tech, alert.RiskScore)
				fmt.Printf("          Timestamp: %s\n\n", alert.Timestamp.Format("15:04:05"))
			}

			if cfg.AI.Backend != "none" && cfg.AI.Backend != "" {
				aiCmds, err := ai.NewCommands(cfg.AI)
				if err == nil {
					resp, err := aiCmds.ExplainIncident(ctx, inc)
					if err == nil {
						fmt.Println("🤖 AI Analyst Reconstruction:")
						fmt.Println("--------------------------------------------------")
						fmt.Println(resp)
						fmt.Println("--------------------------------------------------")
					}
				}
			}

			return nil
		},
	}
}
