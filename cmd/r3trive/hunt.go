package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/internal/intelligence/hunter"
	"github.com/thrive-spectrexq/r3trive/internal/output"
)

var (
	huntTechnique string
	huntRuleset   string
	huntTargetDir string
	huntOutput    string
)

func newHuntCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hunt",
		Short: "Active threat hunting across host artifacts and rulesets",
		Long: `Performs proactive threat hunting across running processes, host binaries,
YARA rules, Sigma rules, and MITRE ATT&CK techniques.`,
		RunE: runHunt,
	}

	cmd.Flags().StringVar(&huntTechnique, "technique", "", "filter hunt by MITRE ATT&CK technique ID (e.g. T1003)")
	cmd.Flags().StringVar(&huntRuleset, "ruleset", "", "path to directory containing custom YARA or Sigma rules")
	cmd.Flags().StringVar(&huntTargetDir, "dir", "", "target directory to hunt for suspicious artifacts")
	cmd.Flags().StringVarP(&huntOutput, "output", "o", "table", "output format: table, json, ndjson")

	return cmd
}

func runHunt(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	yScanner := yara.NewScanner()
	h := hunter.New(yScanner)

	opts := hunter.HuntOptions{
		Technique: huntTechnique,
		Ruleset:   huntRuleset,
		TargetDir: huntTargetDir,
		OutputFmt: huntOutput,
	}

	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE Threat Hunting Engine")
	if huntTechnique != "" {
		fmt.Printf(" Technique Filter: %s\n", huntTechnique)
	}
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	res, err := h.Hunt(ctx, opts)
	if err != nil {
		return fmt.Errorf("executing threat hunt: %w", err)
	}

	outFmt, _ := output.ParseFormat(huntOutput)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	if outFmt == output.FormatJSON || outFmt == output.FormatNDJSON {
		return formatter.WriteObject(res)
	}

	fmt.Printf("Scanned %d items | Found %d threat indicators\n\n", res.TotalScanned, res.MatchesCount)
	if len(res.Findings) == 0 {
		fmt.Println("No threat findings detected.")
		return nil
	}

	fmt.Printf("%-10s %-12s %-25s %-30s %s\n", "SEVERITY", "CATEGORY", "RULE / INDICATOR", "ARTIFACT", "TECHNIQUE")
	fmt.Println("──────────────────────────────────────────────────────────────────────────────────────────")

	for _, f := range res.Findings {
		tech := f.Technique
		if tech == "" {
			tech = "N/A"
		}
		fmt.Printf("%-10s %-12s %-25s %-30s %s\n",
			f.Severity, f.Category, truncateString(f.RuleName, 25), truncateString(f.Artifact, 30), tech)
	}

	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
