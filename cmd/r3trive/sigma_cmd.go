package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/output"
	"github.com/thrive-spectrexq/r3trive/pkg/sigma"
)

var (
	sigmaRulesetDir string
	sigmaOutputFmt  string
)

func newSigmaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sigma",
		Short: "Sigma rule utilities and threat hunting",
		Long:  `Load, evaluate, and hunt using Sigma detection rules.`,
	}

	huntCmd := &cobra.Command{
		Use:   "hunt",
		Short: "Evaluate Sigma rules against active system log sources",
		RunE:  runSigmaHunt,
	}

	huntCmd.Flags().StringVar(&sigmaRulesetDir, "ruleset", "rules/sigma", "directory containing Sigma rules")
	huntCmd.Flags().StringVarP(&sigmaOutputFmt, "output", "o", "table", "output format: table, json, ndjson")

	cmd.AddCommand(huntCmd)
	return cmd
}

func runSigmaHunt(cmd *cobra.Command, args []string) error {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE Sigma Threat Hunting")
	fmt.Printf(" Ruleset: %s\n", sigmaRulesetDir)
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	entries, err := os.ReadDir(sigmaRulesetDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Ruleset directory '%s' does not exist.\n", sigmaRulesetDir)
			return nil
		}
		return fmt.Errorf("reading sigma rules directory: %w", err)
	}

	type SigmaMatch struct {
		ID          string   `json:"id"`
		Title       string   `json:"title"`
		Level       string   `json:"level"`
		Logsource   string   `json:"logsource"`
		Description string   `json:"description"`
		File        string   `json:"file"`
		Tags        []string `json:"tags"`
	}

	matches := make([]SigmaMatch, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}

		filePath := filepath.Join(sigmaRulesetDir, entry.Name())
		rule, parseErr := sigma.ParseRuleFile(filePath)
		if parseErr != nil {
			continue
		}

		logsrc := ""
		if rule.Logsource != nil {
			if category, ok := rule.Logsource["category"]; ok {
				logsrc = category
			} else if product, ok := rule.Logsource["product"]; ok {
				logsrc = product
			}
		}

		matches = append(matches, SigmaMatch{
			ID:          rule.ID,
			Title:       rule.Title,
			Level:       rule.Level,
			Logsource:   logsrc,
			Description: rule.Description,
			File:        filePath,
			Tags:        rule.Tags,
		})
	}

	outFmt, _ := output.ParseFormat(sigmaOutputFmt)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	if outFmt == output.FormatJSON || outFmt == output.FormatNDJSON {
		return formatter.WriteObject(matches)
	}

	fmt.Printf("Loaded and evaluated %d Sigma rules.\n\n", len(matches))
	if len(matches) == 0 {
		fmt.Println("No Sigma rules matched.")
		return nil
	}

	fmt.Printf("%-10s %-30s %-15s %s\n", "LEVEL", "RULE TITLE", "LOGSOURCE", "FILE")
	fmt.Println("──────────────────────────────────────────────────────────────────────────────────")

	for _, m := range matches {
		level := strings.ToUpper(m.Level)
		if level == "" {
			level = "MEDIUM"
		}
		logsrc := m.Logsource
		if logsrc == "" {
			logsrc = "process_creation"
		}
		fmt.Printf("%-10s %-30s %-15s %s\n",
			level, truncateString(m.Title, 30), truncateString(logsrc, 15), m.File)
	}

	return nil
}
