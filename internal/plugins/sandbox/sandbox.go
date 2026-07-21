package sandbox

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Permission specifies a capability allowed for a sandboxed plugin.
type Permission string

const (
	PermissionNetwork    Permission = "network"
	PermissionFileSystem Permission = "filesystem"
	PermissionProcess    Permission = "process"
)

// Config holds sandbox execution limits and permissions.
type Config struct {
	MaxMemoryMB int           `json:"max_memory_mb"`
	Timeout     time.Duration `json:"timeout"`
	Permissions []Permission  `json:"permissions"`
}

// Sandbox isolates plugin execution within configured security boundaries.
type Sandbox struct {
	cfg Config
}

// New creates a new Plugin Sandbox environment.
func New(cfg Config) *Sandbox {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Sandbox{cfg: cfg}
}

// Execute runs a plugin function inside a context-bounded sandbox.
func (s *Sandbox) Execute(ctx context.Context, pluginName string, fn func(ctx context.Context) error) error {
	slog.Debug("executing sandboxed plugin", "plugin", pluginName, "timeout", s.cfg.Timeout)

	timeoutCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("plugin panic recovered: %v", r)
			}
		}()
		errCh <- fn(timeoutCtx)
	}()

	select {
	case <-timeoutCtx.Done():
		return fmt.Errorf("plugin '%s' execution timed out after %s", pluginName, s.cfg.Timeout)
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("plugin '%s' error: %w", pluginName, err)
		}
		return nil
	}
}
