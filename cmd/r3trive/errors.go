package main

import (
	"errors"
	"strings"
)

// Standard operational exit codes for R3TRIVE CLI.
const (
	// ExitSuccess indicates normal, successful execution.
	ExitSuccess = 0
	// ExitGeneralError indicates an unexpected runtime failure.
	ExitGeneralError = 1
	// ExitConfigError indicates invalid configuration, syntax error, or bad command flag.
	ExitConfigError = 2
	// ExitPermissionError indicates insufficient OS permissions (e.g., Administrator / root required).
	ExitPermissionError = 3
	// ExitStorageError indicates database connectivity, migration, or persistence failure.
	ExitStorageError = 4
	// ExitPlatformError indicates unsupported operating system or missing sensor kernel subsystem.
	ExitPlatformError = 5
)

// ConfigError represents a configuration or flag validation failure.
type ConfigError struct {
	Msg string
}

func (e *ConfigError) Error() string { return e.Msg }

// PermissionError represents insufficient OS privileges.
type PermissionError struct {
	Msg string
}

func (e *PermissionError) Error() string { return e.Msg }

// StorageError represents a database connection or storage failure.
type StorageError struct {
	Msg string
}

func (e *StorageError) Error() string { return e.Msg }

// PlatformError represents an unsupported OS or missing kernel feature.
type PlatformError struct {
	Msg string
}

func (e *PlatformError) Error() string { return e.Msg }

// classifyError inspects an error and maps it to an exit code and descriptive category.
func classifyError(err error) (int, string) {
	if err == nil {
		return ExitSuccess, "Success"
	}

	var cfgErr *ConfigError
	if errors.As(err, &cfgErr) {
		return ExitConfigError, "Configuration Error"
	}

	var permErr *PermissionError
	if errors.As(err, &permErr) {
		return ExitPermissionError, "Permission Error"
	}

	var storErr *StorageError
	if errors.As(err, &storErr) {
		return ExitStorageError, "Storage Error"
	}

	var platErr *PlatformError
	if errors.As(err, &platErr) {
		return ExitPlatformError, "Platform Error"
	}

	errMsg := strings.ToLower(err.Error())

	// Heuristic inspection for common error strings
	switch {
	case strings.Contains(errMsg, "config: ") ||
		strings.Contains(errMsg, "invalid storage driver") ||
		strings.Contains(errMsg, "invalid log_level") ||
		strings.Contains(errMsg, "invalid output_format") ||
		strings.Contains(errMsg, "unknown flag") ||
		strings.Contains(errMsg, "required flag") ||
		strings.Contains(errMsg, "flag provided but not defined") ||
		strings.Contains(errMsg, "unknown command"):
		return ExitConfigError, "Configuration Error"

	case strings.Contains(errMsg, "access is denied") ||
		strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "administrator") ||
		strings.Contains(errMsg, "operation not permitted") ||
		strings.Contains(errMsg, "elevated"):
		return ExitPermissionError, "Permission Error"

	case strings.Contains(errMsg, "sqlite:") ||
		strings.Contains(errMsg, "postgres:") ||
		strings.Contains(errMsg, "database is locked") ||
		strings.Contains(errMsg, "failed to connect to `user=") ||
		strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "no connection could be made"):
		return ExitStorageError, "Storage Error"

	case strings.Contains(errMsg, "unsupported os") ||
		strings.Contains(errMsg, "unsupported platform") ||
		strings.Contains(errMsg, "kernel") ||
		strings.Contains(errMsg, "not implemented on"):
		return ExitPlatformError, "Platform Error"

	default:
		return ExitGeneralError, "Runtime Error"
	}
}
