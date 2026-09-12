package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/intelligence/hunter"
	"github.com/thrive-spectrexq/r3trive/internal/output"
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

	ctx := context.Background()
	h := hunter.New(nil)
	res, err := h.Hunt(ctx, hunter.HuntOptions{
		Ruleset: sigmaRulesetDir,
	})
	if err != nil {
		return fmt.Errorf("sigma hunt failed: %w", err)
	}

	outFmt, _ := output.ParseFormat(sigmaOutputFmt)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	if outFmt == output.FormatJSON || outFmt == output.FormatNDJSON {
		return formatter.WriteObject(res)
	}

	fmt.Printf("Evaluated Sigma rules across active system processes (Total scanned: %d, Matches: %d)\n\n",
		res.TotalScanned, res.MatchesCount)

	if len(res.Findings) == 0 {
		fmt.Println("No Sigma rule violations detected on current host.")
		return nil
	}

	fmt.Printf("%-10s %-30s %-15s %s\n", "LEVEL", "RULE TITLE", "TECHNIQUE", "ARTIFACT")
	fmt.Println("──────────────────────────────────────────────────────────────────────────────────")

	for _, f := range res.Findings {
		fmt.Printf("%-10s %-30s %-15s %s\n",
			strings.ToUpper(string(f.Severity)),
			truncateString(f.RuleName, 30),
			truncateString(f.Technique, 15),
			f.Artifact,
		)
	}

	return nil
}
