package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/audit"
	"github.com/thrive-spectrexq/r3trive/internal/output"
)

var (
	auditProfile string
	auditQuick   bool
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run security baseline assessment",
		Long: `Performs a security audit of the current host, checking firewall
status, user account policies, open ports, startup programs, and
other security-relevant configurations.`,
		RunE: runAudit,
	}

	cmd.Flags().StringVar(&auditProfile, "profile", "quick", "audit profile: quick, cis-level1, cis-level2")
	cmd.Flags().BoolVar(&auditQuick, "quick", false, "run quick audit (same as --profile quick)")

	return cmd
}

func runAudit(cmd *cobra.Command, args []string) error {
	if auditQuick {
		auditProfile = "quick"
	}

	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE Security Audit")
	fmt.Printf(" Profile: %s\n", auditProfile)
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// Run audit engine
	engine := audit.NewEngine()
	results, err := engine.Run(auditProfile)
	if err != nil {
		return fmt.Errorf("running audit: %w", err)
	}

	// Display results
	outFmt, _ := output.ParseFormat(cfg.OutputFmt)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	switch outFmt {
	case output.FormatJSON, output.FormatNDJSON:
		if err := formatter.WriteObject(results); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	default:
		printAuditResults(results)
	}

	return nil
}

func printAuditResults(results *audit.Results) {
	// Summary
	fmt.Printf("  Checks run: %d\n", results.Total)
	fmt.Printf("  Passed:     %d ✓\n", results.Passed)
	fmt.Printf("  Failed:     %d ✗\n", results.Failed)
	fmt.Printf("  Warnings:   %d ⚠\n", results.Warnings)
	fmt.Printf("  Skipped:    %d ○\n", results.Skipped)
	fmt.Println()

	// Score bar
	scorePercent := 0
	if results.Total > 0 {
		scorePercent = (results.Passed * 100) / results.Total
	}
	barLen := 30
	filled := (scorePercent * barLen) / 100
	bar := ""
	for i := 0; i < barLen; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	fmt.Printf("  Score: %d%% %s\n", scorePercent, bar)
	fmt.Println()

	// Individual results
	for _, check := range results.Checks {
		icon := "✓"
		switch check.Status {
		case audit.StatusFail:
			icon = "✗"
		case audit.StatusWarn:
			icon = "⚠"
		case audit.StatusSkip:
			icon = "○"
		}
		fmt.Printf("  %s [%s] %s\n", icon, check.Category, check.Name)
		if check.Status == audit.StatusFail || check.Status == audit.StatusWarn {
			fmt.Printf("      %s\n", check.Detail)
		}
	}
	fmt.Println()
}
