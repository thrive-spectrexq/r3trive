package ai

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/config"
)

func TestNewClientDisabled(t *testing.T) {
	cfg := config.AIConfig{Backend: "none"}
	_, err := NewClient(cfg)
	if err == nil {
		t.Errorf("expected error for backend 'none', got nil")
	}
}

func TestOllamaClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response": "analyzed output"}`))
	}))
	defer ts.Close()

	cfg := config.AIConfig{
		Backend:  "ollama",
		Endpoint: ts.URL,
		Model:    "llama3",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create Ollama client: %v", err)
	}

	res, err := client.Chat(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if res != "analyzed output" {
		t.Errorf("expected 'analyzed output', got %q", res)
	}
}

func TestOpenAIClient(t *testing.T) {
	authHeaderReceived := ""

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaderReceived = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices": [{"message": {"content": "openai response"}}]}`))
	}))
	defer ts.Close()

	cfg := config.AIConfig{
		Backend:  "openai",
		Endpoint: ts.URL,
		Model:    "gpt-4o",
		APIKey:   "test-secret-key",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create OpenAI client: %v", err)
	}

	res, err := client.Chat(context.Background(), "explain threat")
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if res != "openai response" {
		t.Errorf("expected 'openai response', got %q", res)
	}
	if authHeaderReceived != "Bearer test-secret-key" {
		t.Errorf("expected Authorization header 'Bearer test-secret-key', got %q", authHeaderReceived)
	}
}

type flakyMockClient struct {
	failTimes int
	attempts  int
}

func (f *flakyMockClient) Chat(ctx context.Context, prompt string) (string, error) {
	f.attempts++
	if f.attempts <= f.failTimes {
		return "", errors.New("transient upstream failure")
	}
	return "recovered output", nil
}

func TestRetryingClient_SuccessAfterTransientError(t *testing.T) {
	flaky := &flakyMockClient{failTimes: 2}
	retrying := NewRetryingClient(flaky, 3, 10*time.Millisecond)

	res, err := retrying.Chat(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if res != "recovered output" {
		t.Errorf("expected 'recovered output', got %q", res)
	}
	if flaky.attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", flaky.attempts)
	}
}

func TestRetryingClient_ExhaustsRetries(t *testing.T) {
	flaky := &flakyMockClient{failTimes: 5}
	retrying := NewRetryingClient(flaky, 2, 10*time.Millisecond)

	_, err := retrying.Chat(context.Background(), "test prompt")
	if err == nil {
		t.Fatalf("expected error after exhausting retries, got nil")
	}
	if flaky.attempts != 3 { // 1 initial + 2 retries = 3 attempts
		t.Errorf("expected 3 attempts before failure, got %d", flaky.attempts)
	}
}

