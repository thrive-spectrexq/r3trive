package router

import (
	"context"
	"errors"
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
