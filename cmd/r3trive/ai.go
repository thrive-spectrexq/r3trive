package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/ai"
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
		Use:   "explain [event-id]",
		Short: "Ask the AI to explain a specific event or alert",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// To be fully implemented: retrieve event by ID from storage
			// and call ExplainEvent or ExplainAlert.
			fmt.Printf("🔍 Extracting context for %s...\n", args[0])
			fmt.Println("🤖 AI explanation would appear here (Storage retrieval pending).")
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
			// To be fully implemented: retrieve events in timeframe
			// and call Summarize.
			fmt.Printf("📊 Summarizing activity for the last %s...\n", args[0])
			fmt.Println("🤖 AI summary would appear here (Storage retrieval pending).")
			return nil
		},
	}
}
