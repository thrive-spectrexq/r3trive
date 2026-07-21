package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/internal/output"
)

var (
	yaraDir       string
	yaraRecursive bool
	yaraRulesDir  string
	yaraOutputFmt string
)

func newYaraCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "yara",
		Short: "YARA rule scanning utilities",
		Long:  `Scan binaries, files, or directories using YARA signatures.`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [target_path]",
		Short: "Scan a file or directory with YARA rules",
		RunE:  runYaraScan,
	}

	scanCmd.Flags().StringVar(&yaraDir, "dir", "", "directory to scan")
	scanCmd.Flags().BoolVarP(&yaraRecursive, "recursive", "r", false, "scan directories recursively")
	scanCmd.Flags().StringVar(&yaraRulesDir, "rules", "rules/yara", "directory containing YARA rules")
	scanCmd.Flags().StringVarP(&yaraOutputFmt, "output", "o", "table", "output format: table, json, ndjson")

	cmd.AddCommand(scanCmd)
	return cmd
}

func runYaraScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	targetPath := yaraDir
	if len(args) > 0 && args[0] != "" {
		targetPath = args[0]
	}

	if targetPath == "" {
		return fmt.Errorf("must specify a target file or directory path")
	}

	scanner := yara.NewScanner()
	if err := scanner.LoadRules(yaraRulesDir); err != nil {
		fmt.Printf("Warning: failed to load YARA rules from %s: %v\n", yaraRulesDir, err)
	}

	info, err := os.Stat(targetPath)
	if err != nil {
		return fmt.Errorf("stat target path %s: %w", targetPath, err)
	}

	type YMatchResult struct {
		Path  string       `json:"path"`
		Rules []yara.Match `json:"rules"`
	}

	var results []YMatchResult

	if !info.IsDir() {
		matches, err := scanner.ScanFile(ctx, targetPath)
		if err != nil {
			return fmt.Errorf("scanning file %s: %w", targetPath, err)
		}
		if len(matches) > 0 {
			results = append(results, YMatchResult{Path: targetPath, Rules: matches})
		}
	} else {
		err := filepath.Walk(targetPath, func(path string, f os.FileInfo, walkErr error) error {
			if walkErr != nil || f == nil || f.IsDir() {
				if !yaraRecursive && path != targetPath && f != nil && f.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			matches, scanErr := scanner.ScanFile(ctx, path)
			if scanErr == nil && len(matches) > 0 {
				results = append(results, YMatchResult{Path: path, Rules: matches})
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("directory walk failed: %w", err)
		}
	}

	outFmt, _ := output.ParseFormat(yaraOutputFmt)
	formatter := output.NewFormatter(os.Stdout, outFmt)

	if outFmt == output.FormatJSON || outFmt == output.FormatNDJSON {
		return formatter.WriteObject(results)
	}

	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" R3TRIVE YARA Scan Results")
	fmt.Printf(" Target: %s | Ruleset: %s\n", targetPath, yaraRulesDir)
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	if len(results) == 0 {
		fmt.Println("No YARA rule matches detected.")
		return nil
	}

	for _, res := range results {
		fmt.Printf("File: %s\n", res.Path)
		for _, m := range res.Rules {
			tagsStr := strings.Join(m.Tags, ", ")
			if tagsStr == "" {
				tagsStr = "none"
			}
			fmt.Printf("  └─ [MATCH] Rule: %s | Tags: %s\n", m.Rule, tagsStr)
		}
	}

	return nil
}
