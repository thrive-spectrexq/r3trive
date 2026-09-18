package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestRootCmdStructure(t *testing.T) {
	rootCmd := newRootCmd()

	subcommands := []string{
		"version", "init", "monitor", "audit", "config", "ask",
		"generate-rule", "defend", "explain", "summarize",
		"hunt", "investigate", "yara", "sigma", "attack-chain", "serve", "plugins",
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
		newPluginsCmd(),
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

func TestPluginsCmdExecution(t *testing.T) {
	rootCmd := newRootCmd()
	rootCmd.AddCommand(newPluginsCmd())

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"plugins", "list", "--verbose"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("plugins list command failed: %v", err)
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode int
	}{
		{"nil error", nil, ExitSuccess},
		{"config flag error", &ConfigError{Msg: "unknown flag: --foo"}, ExitConfigError},
		{"config text error", fmt.Errorf("config: validating: invalid storage driver"), ExitConfigError},
		{"permission error", &PermissionError{Msg: "administrator privileges required"}, ExitPermissionError},
		{"access denied", fmt.Errorf("open C:\\Windows\\System32: access is denied"), ExitPermissionError},
		{"storage error", &StorageError{Msg: "failed to connect to postgres"}, ExitStorageError},
		{"storage text error", fmt.Errorf("sqlite: database is locked"), ExitStorageError},
		{"platform error", &PlatformError{Msg: "unsupported OS: freebsd"}, ExitPlatformError},
		{"general error", fmt.Errorf("something unexpected occurred"), ExitGeneralError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _ := classifyError(tt.err)
			if code != tt.expectedCode {
				t.Errorf("classifyError(%v) = %d, expected %d", tt.err, code, tt.expectedCode)
			}
		})
	}
}
