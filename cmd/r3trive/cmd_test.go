package main

import (
	"bytes"
	"testing"
)

func TestRootCmdStructure(t *testing.T) {
	rootCmd := newRootCmd()

	subcommands := []string{
		"version", "init", "monitor", "audit", "config", "ask",
		"generate-rule", "defend", "explain", "summarize",
		"hunt", "investigate", "yara", "sigma", "attack-chain", "serve",
	}

	rootCmd.AddCommand(
		newVersionCmd(),
		newInitCmd(),
		newMonitorCmd(),
		newAuditCmd(),
		newConfigCmd(),
		newAskCmd(),
		newGenerateRuleCmd(),
		newDefendCmd(),
		newExplainCmd(),
		newSummarizeCmd(),
		newHuntCmd(),
		newInvestigateCmd(),
		newYaraCmd(),
		newSigmaCmd(),
		newAttackChainCmd(),
		newServeCmd(),
	)

	for _, sub := range subcommands {
		cmd, _, err := rootCmd.Find([]string{sub})
		if err != nil || cmd == nil || cmd.Name() != sub {
			t.Errorf("expected subcommand %s to be registered", sub)
		}
	}
}

func TestVersionCmdExecution(t *testing.T) {
	rootCmd := newRootCmd()
	rootCmd.AddCommand(newVersionCmd())

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}
}
