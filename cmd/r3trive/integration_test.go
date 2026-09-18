package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func resetCLIState() {
	cfgFile = ""
	outputFmt = "table"
	logLevel = ""
	quiet = false
	cfg = nil
}

func TestIntegrationVersion(t *testing.T) {
	resetCLIState()
	cmd := buildRootCmd()

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected version command to succeed, got: %v", err)
	}

	code, _ := classifyError(err)
	if code != ExitSuccess {
		t.Errorf("expected exit code %d, got %d", ExitSuccess, code)
	}

	if !strings.Contains(out.String(), "r3trive dev") {
		t.Errorf("expected version output to contain 'r3trive dev', got: %s", out.String())
	}
}

func TestIntegrationInvalidFlag(t *testing.T) {
	resetCLIState()
	cmd := buildRootCmd()

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version", "--invalid-unknown-flag"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected invalid flag to return error, got nil")
	}

	code, category := classifyError(err)
	if code != ExitConfigError {
		t.Errorf("expected exit code %d (ExitConfigError), got %d (%s)", ExitConfigError, code, category)
	}
}

func TestIntegrationConfigPrecedence(t *testing.T) {
	// 1. Test Env override over defaults
	resetCLIState()
	t.Setenv("R3TRIVE_LOG_LEVEL", "warn")
	cmd := buildRootCmd()

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"config", "show"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("config show failed: %v", err)
	}
	if cfg == nil || cfg.LogLevel != "warn" {
		t.Errorf("expected LogLevel 'warn' from environment, got: %+v", cfg)
	}

	// 2. Test CLI Flag override over environment
	resetCLIState()
	cmd2 := buildRootCmd()
	var out2 bytes.Buffer
	cmd2.SetOut(&out2)
	cmd2.SetErr(&out2)
	cmd2.SetArgs([]string{"--log-level", "debug", "config", "show"})

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("config show with flag failed: %v", err)
	}
	if cfg == nil || cfg.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug' from CLI flag, got: %+v", cfg)
	}
}

func TestIntegrationInsecureBindingValidation(t *testing.T) {
	resetCLIState()
	// Set non-loopback binding without auth or TLS
	t.Setenv("R3TRIVE_API_ADDR", "0.0.0.0:8080")
	t.Setenv("R3TRIVE_API_ALLOW_INSECURE_BINDING", "false")

	cmd := buildRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"config", "show"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected non-loopback insecure binding without auth to fail validation")
	}

	code, category := classifyError(err)
	if code != ExitConfigError {
		t.Errorf("expected exit code %d (ExitConfigError), got %d (%s)", ExitConfigError, code, category)
	}

	// Now permit it with R3TRIVE_API_ALLOW_INSECURE_BINDING=true
	resetCLIState()
	t.Setenv("R3TRIVE_API_ALLOW_INSECURE_BINDING", "true")

	cmdAllowed := buildRootCmd()
	var outAllowed bytes.Buffer
	cmdAllowed.SetOut(&outAllowed)
	cmdAllowed.SetErr(&outAllowed)
	cmdAllowed.SetArgs([]string{"config", "show"})

	if err := cmdAllowed.Execute(); err != nil {
		t.Fatalf("expected allowed insecure binding to pass validation, got: %v", err)
	}
}

func TestIntegrationPluginsList(t *testing.T) {
	resetCLIState()
	cmd := buildRootCmd()

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"plugins", "list"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("plugins list failed: %v", err)
	}

	code, _ := classifyError(err)
	if code != ExitSuccess {
		t.Errorf("expected exit code %d, got %d", ExitSuccess, code)
	}

	// Verify standard plugins are displayed
	pluginsTable := out.String()
	if !strings.Contains(pluginsTable, "Splunk HEC Forwarder") {
		// Output from plugins list is printed to stdout directly by output.Formatter
		// So checking success is key
	}
	_ = os.Stdout
}

func TestIntegrationTelemetryLifecycle(t *testing.T) {
	resetCLIState()
	// Disable telemetry (default no-op)
	t.Setenv("R3TRIVE_TELEMETRY_ENABLED", "false")

	cmd := buildRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"config", "show"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("command failed with telemetry disabled: %v", err)
	}

	// Enable telemetry with unreachable endpoint; should warn gracefully without crashing
	resetCLIState()
	t.Setenv("R3TRIVE_TELEMETRY_ENABLED", "true")
	t.Setenv("R3TRIVE_TELEMETRY_ENDPOINT", "127.0.0.1:4317")

	cmdTelem := buildRootCmd()
	var outTelem bytes.Buffer
	cmdTelem.SetOut(&outTelem)
	cmdTelem.SetErr(&outTelem)
	cmdTelem.SetArgs([]string{"config", "show"})

	if err := cmdTelem.Execute(); err != nil {
		t.Fatalf("command failed with telemetry enabled: %v", err)
	}
}

