package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
