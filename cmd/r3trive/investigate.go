package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/internal/intelligence/investigator"
	"github.com/thrive-spectrexq/r3trive/internal/output"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/storage/sqlite"
)

var (
	investigatePID      int
	investigateIncident string
	investigateOutput   string
)

func newInvestigateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "investigate [file_path]",
		Short: "Deep diagnostic analysis of binaries, processes, or incidents",
		Long: `Deep investigation of suspicious binaries, active process IDs, or stored incidents
with risk scoring, ATT&CK technique mapping, and response recommendations.`,
		RunE: runInvestigate,
	}

	cmd.Flags().IntVar(&investigatePID, "pid", 0, "target process ID to investigate")
	cmd.Flags().StringVar(&investigateIncident, "incident", "", "incident ID stored in database to investigate")
	cmd.Flags().StringVarP(&investigateOutput, "output", "o", "table", "output format: table, json, ndjson")

	return cmd
}

func runInvestigate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	var store storage.Store
	if cfg != nil && cfg.Storage.Driver == "sqlite" {
		sqliteStore, err := sqlite.New(cfg.Storage.DSN)
		if err == nil {
			store = sqliteStore
			defer store.Close()
		}
	}

	yScanner := yara.NewScanner()
	inv := investigator.New(yScanner, store)

	var report *investigator.InvestigationReport
	var err error

	switch {
	case len(args) > 0 && args[0] != "":
		filePath := args[0]
		report, err = inv.InvestigateBinary(ctx, filePath)
	case investigatePID > 0:
		report, err = inv.InvestigateProcess(ctx, investigatePID)
	case investigateIncident != "":
		report, err = inv.InvestigateIncident(ctx, investigateIncident)
	default:
		return fmt.Errorf("must specify target binary path, --pid, or --incident")
	}

	if err != nil {
		return fmt.Errorf("investigation failed: %w", err)
	}

	outFmt, _ := output.ParseFormat(investigateOutput)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	if outFmt == output.FormatJSON || outFmt == output.FormatNDJSON {
		return formatter.WriteObject(report)
	}

	// Print Terminal Report
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE Incident Investigation Report")
	fmt.Printf(" Target: %s\n", report.Target)
	fmt.Printf(" Timestamp: %s\n", report.Timestamp.Format("2006-01-02T15:04:05Z"))
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	bar := renderProgressBar(report.RiskScore)
	fmt.Printf("Risk Score: %d / 100  %s %s\n\n", report.RiskScore, bar, strings.ToUpper(string(report.Severity)))

	fmt.Println("Findings:")
	if len(report.Findings) == 0 {
		fmt.Println("  [INFO] No critical threat indicators found.")
	} else {
		for _, f := range report.Findings {
			fmt.Printf("  [%-8s] %s\n", strings.ToUpper(string(f.Severity)), f.Message)
		}
	}

	fmt.Println("\nATT&CK Techniques:")
	if len(report.ATTACKTechniques) == 0 {
		fmt.Println("  None mapped")
	} else {
		for _, tech := range report.ATTACKTechniques {
			fmt.Printf("  %-10s %s\n", tech.Technique, tech.Name)
		}
	}

	fmt.Printf("\nRecommended Action: %s\n", report.RecommendedAction)
	return nil
}

func renderProgressBar(score int) string {
	totalBlocks := 20
	filled := (score * totalBlocks) / 100
	if filled < 0 {
		filled = 0
	}
	if filled > totalBlocks {
		filled = totalBlocks
	}

	var sb strings.Builder
	for i := 0; i < filled; i++ {
		sb.WriteString("█")
	}
	for i := filled; i < totalBlocks; i++ {
		sb.WriteString("░")
	}
	return sb.String()
}
