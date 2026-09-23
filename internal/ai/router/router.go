package router

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/ai"
	"github.com/thrive-spectrexq/r3trive/internal/config"
)

// Client defines the interface for communicating with an AI model backend.
type Client interface {
	Chat(ctx context.Context, prompt string) (string, error)
	Name() string
}

// ClientMetrics tracks health and request performance for a client.
type ClientMetrics struct {
	TotalRequests int64
	Successes     int64
	Failures      int64
	LastErrorTime time.Time
	IsHealthy     bool
}

var (
	emailRegex     = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	privateIPRegex = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	tokenRegex     = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9\-\._~+/]+=*|api[_-]?key[:=\s]+["']?[A-Za-z0-9\-\._~+/]+["']?)`)
	passwordRegex  = regexp.MustCompile(`(?i)(-(?:p|password)|--(?:password|secret))\s+([^\s]+)`)
)

// RedactPII masks private internal IPs, credentials, bearer tokens, and emails from AI prompts.
func RedactPII(input string) string {
	out := emailRegex.ReplaceAllString(input, "[REDACTED_EMAIL]")
	out = tokenRegex.ReplaceAllString(out, "[REDACTED_TOKEN]")
	out = passwordRegex.ReplaceAllString(out, "$1 [REDACTED_SECRET]")
	out = privateIPRegex.ReplaceAllString(out, "[REDACTED_INTERNAL_IP]")
	return out
}

// Router dispatches prompts to primary and fallback AI model clients with circuit breaking.
type Router struct {
	mu            sync.RWMutex
	primary       Client
	fallbacks     []Client
	stats         map[string]*ClientMetrics
	cooldownTime  time.Duration
	redactPrompts bool
}

// SetRedactPrompts configures whether outbound prompts should have PII and internal secrets redacted.
func (r *Router) SetRedactPrompts(redact bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.redactPrompts = redact
}

// New creates a new AI model router with automatic fallback logic.
func New(primary Client, fallbacks ...Client) *Router {
	r := &Router{
		primary:       primary,
		fallbacks:     fallbacks,
		stats:         make(map[string]*ClientMetrics),
		cooldownTime:  30 * time.Second,
		redactPrompts: true, // Default to secure PII redaction for safety
	}

	if primary != nil {
		r.stats[primary.Name()] = &ClientMetrics{IsHealthy: true}
	}
	for _, fb := range fallbacks {
		if fb != nil {
			r.stats[fb.Name()] = &ClientMetrics{IsHealthy: true}
		}
	}

	return r
}

// Chat dispatches a prompt to the primary model, attempting fallbacks if primary fails or is unhealthy.
func (r *Router) Chat(ctx context.Context, prompt string) (string, error) {
	r.mu.RLock()
	primary := r.primary
	fallbacks := make([]Client, len(r.fallbacks))
	copy(fallbacks, r.fallbacks)
	redact := r.redactPrompts
	r.mu.RUnlock()

	outboundPrompt := prompt
	if redact {
		outboundPrompt = RedactPII(prompt)
	}

	// Try Primary first if healthy or cooled down
	if primary != nil && r.isClientAvailable(primary.Name()) {
		slog.Debug("dispatching AI prompt to primary backend", "client", primary.Name())
		res, err := primary.Chat(ctx, outboundPrompt)
		if err == nil {
			r.recordSuccess(primary.Name())
			return res, nil
		}
		r.recordFailure(primary.Name(), err)
		slog.Warn("primary AI backend failed, attempting fallback", "client", primary.Name(), "error", err)
	}

	// Try fallbacks in sequence
	for _, fb := range fallbacks {
		if fb == nil || !r.isClientAvailable(fb.Name()) {
			continue
		}
		slog.Info("attempting fallback AI backend", "client", fb.Name())
		res, err := fb.Chat(ctx, outboundPrompt)
		if err == nil {
			r.recordSuccess(fb.Name())
			return res, nil
		}
		r.recordFailure(fb.Name(), err)
		slog.Warn("fallback AI backend failed", "client", fb.Name(), "error", err)
	}

	return "", fmt.Errorf("all AI backends failed to produce a response")
}

// GetMetrics returns operational health metrics for all registered clients.
func (r *Router) GetMetrics() map[string]ClientMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]ClientMetrics)
	for k, v := range r.stats {
		result[k] = ClientMetrics{
			TotalRequests: atomic.LoadInt64(&v.TotalRequests),
			Successes:     atomic.LoadInt64(&v.Successes),
			Failures:      atomic.LoadInt64(&v.Failures),
			LastErrorTime: v.LastErrorTime,
			IsHealthy:     v.IsHealthy,
		}
	}
	return result
}

func (r *Router) isClientAvailable(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	m, ok := r.stats[name]
	if !ok {
		return true
	}
	if m.IsHealthy {
		return true
	}
	// Check if cooldown elapsed to retry
	return time.Since(m.LastErrorTime) > r.cooldownTime
}

func (r *Router) recordSuccess(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m, ok := r.stats[name]
	if !ok {
		m = &ClientMetrics{IsHealthy: true}
		r.stats[name] = m
	}
	atomic.AddInt64(&m.TotalRequests, 1)
	atomic.AddInt64(&m.Successes, 1)
	m.IsHealthy = true
}

func (r *Router) recordFailure(name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m, ok := r.stats[name]
	if !ok {
		m = &ClientMetrics{}
		r.stats[name] = m
	}
	atomic.AddInt64(&m.TotalRequests, 1)
	atomic.AddInt64(&m.Failures, 1)
	m.LastErrorTime = time.Now()
	m.IsHealthy = false
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
