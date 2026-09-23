package router

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/thrive-spectrexq/r3trive/internal/config"
)

type dummyClient struct {
	name string
	fail bool
	resp string
}

func (d *dummyClient) Chat(ctx context.Context, prompt string) (string, error) {
	if d.fail {
		return "", errors.New("backend failed")
	}
	return d.resp, nil
}

func (d *dummyClient) Name() string {
	return d.name
}

func TestRouterFallback(t *testing.T) {
	primary := &dummyClient{name: "Primary", fail: true}
	fallback := &dummyClient{name: "Fallback", fail: false, resp: "fallback output"}

	r := New(primary, fallback)
	res, err := r.Chat(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("expected router fallback success, got: %v", err)
	}

	if res != "fallback output" {
		t.Errorf("expected 'fallback output', got %q", res)
	}
}

func TestSelectClientMock(t *testing.T) {
	cfg := config.AIConfig{Backend: "mock", Model: "test-model"}
	c := SelectClient(cfg)
	if c.Name() != "MockClient(test-model)" {
		t.Errorf("expected MockClient(test-model), got %s", c.Name())
	}
}

func TestRedactPII(t *testing.T) {
	raw := "User analyst@corp.local from 192.168.1.10 executed net use -p Secret123 with Bearer eyJhbGciOi"
	redacted := RedactPII(raw)

	if strings.Contains(redacted, "analyst@corp.local") {
		t.Error("expected email to be redacted")
	}
	if !strings.Contains(redacted, "[REDACTED_EMAIL]") {
		t.Error("expected [REDACTED_EMAIL] placeholder")
	}

	if strings.Contains(redacted, "192.168.1.10") {
		t.Error("expected internal IP to be redacted")
	}
	if !strings.Contains(redacted, "[REDACTED_INTERNAL_IP]") {
		t.Error("expected [REDACTED_INTERNAL_IP] placeholder")
	}

	if strings.Contains(redacted, "Secret123") {
		t.Error("expected password to be redacted")
	}

	if strings.Contains(redacted, "Bearer eyJhbGciOi") {
		t.Error("expected Bearer token to be redacted")
	}
}

func TestRouterPromptRedaction(t *testing.T) {
	var capturedPrompt string
	recorderClient := &inspectClient{
		name: "Recorder",
		onChat: func(p string) {
			capturedPrompt = p
		},
	}

	r := New(recorderClient)
	r.SetRedactPrompts(true)

	_, err := r.Chat(context.Background(), "Connect to 10.0.0.5 for admin@company.com")
	if err != nil {
		t.Fatalf("Chat failed: %v", err)
	}

	if strings.Contains(capturedPrompt, "10.0.0.5") {
		t.Error("outbound prompt contained raw internal IP")
	}
	if strings.Contains(capturedPrompt, "admin@company.com") {
		t.Error("outbound prompt contained raw email")
	}
}

type inspectClient struct {
	name   string
	onChat func(prompt string)
}

func (c *inspectClient) Name() string { return c.name }
func (c *inspectClient) Chat(ctx context.Context, prompt string) (string, error) {
	if c.onChat != nil {
		c.onChat(prompt)
	}
	return "ok", nil
}
