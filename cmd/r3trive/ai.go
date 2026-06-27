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
			
			// Needs to import github.com/thrive-spectrexq/r3trive/internal/storage
			events, err := store.QueryEvents(ctx, storage.EventQuery{
				Since: since,
				Limit: 200, // Fetch up to 200 to give the AI a good sample
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
