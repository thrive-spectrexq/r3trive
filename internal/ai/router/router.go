package router

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/ai"
	"github.com/thrive-spectrexq/r3trive/internal/config"
)

// Client defines the interface for communicating with an AI model backend.
type Client interface {
	Chat(ctx context.Context, prompt string) (string, error)
	Name() string
}

// Router dispatches prompts to primary and fallback AI model clients.
type Router struct {
	primary   Client
	fallbacks []Client
}

// New creates a new AI model router with automatic fallback logic.
func New(primary Client, fallbacks ...Client) *Router {
	return &Router{
		primary:   primary,
		fallbacks: fallbacks,
	}
}

// Chat dispatches a prompt to the primary model, attempting fallbacks if primary fails.
func (r *Router) Chat(ctx context.Context, prompt string) (string, error) {
	if r.primary != nil {
		slog.Debug("dispatching AI prompt to primary backend", "client", r.primary.Name())
		res, err := r.primary.Chat(ctx, prompt)
		if err == nil {
			return res, nil
		}
		slog.Warn("primary AI backend failed, attempting fallback", "client", r.primary.Name(), "error", err)
	}

	for _, fb := range r.fallbacks {
		slog.Info("attempting fallback AI backend", "client", fb.Name())
		res, err := fb.Chat(ctx, prompt)
		if err == nil {
			return res, nil
		}
		slog.Warn("fallback AI backend failed", "client", fb.Name(), "error", err)
	}

	return "", fmt.Errorf("all AI backends failed to produce a response")
}

// MockClient provides a fallback client implementation for offline / testing mode.
type MockClient struct {
	ModelName string
}

func (m *MockClient) Chat(ctx context.Context, prompt string) (string, error) {
	time.Sleep(10 * time.Millisecond)
	return fmt.Sprintf("[Mock Analyst Response (%s)] Analysis completed for prompt.", m.ModelName), nil
}

func (m *MockClient) Name() string {
	return fmt.Sprintf("MockClient(%s)", m.ModelName)
}

// AIClientAdapter wraps an ai.Client to satisfy the router.Client interface.
type AIClientAdapter struct {
	client ai.Client
	name   string
}

func (a *AIClientAdapter) Chat(ctx context.Context, prompt string) (string, error) {
	return a.client.Chat(ctx, prompt)
}

func (a *AIClientAdapter) Name() string {
	return a.name
}

// SelectClient builds a client matching the given configuration.
func SelectClient(cfg config.AIConfig) Client {
	if cfg.Backend == "mock" || cfg.Backend == "" {
		return &MockClient{ModelName: cfg.Model}
	}
	realClient, err := ai.NewClient(cfg)
	if err != nil {
		slog.Warn("failed to initialize AI client, falling back to mock client", "backend", cfg.Backend, "error", err)
		return &MockClient{ModelName: cfg.Model}
	}
	return &AIClientAdapter{
		client: realClient,
		name:   fmt.Sprintf("%s(%s)", cfg.Backend, cfg.Model),
	}
}
