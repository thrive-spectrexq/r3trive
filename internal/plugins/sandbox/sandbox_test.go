package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSandbox_ExecuteSuccess(t *testing.T) {
	sb := New(Config{Timeout: 500 * time.Millisecond})

	executed := false
	err := sb.Execute(context.Background(), "test-plugin", func(ctx context.Context) error {
		executed = true
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !executed {
		t.Fatal("expected function to execute")
	}
}

func TestSandbox_ExecuteError(t *testing.T) {
	sb := New(Config{Timeout: 500 * time.Millisecond})

	expectedErr := errors.New("something went wrong")
	err := sb.Execute(context.Background(), "test-plugin", func(ctx context.Context) error {
		return expectedErr
	})

	if err == nil || !strings.Contains(err.Error(), "something went wrong") {
		t.Fatalf("expected error containing 'something went wrong', got %v", err)
	}
}

func TestSandbox_ExecuteTimeout(t *testing.T) {
	sb := New(Config{Timeout: 50 * time.Millisecond})

	err := sb.Execute(context.Background(), "slow-plugin", func(ctx context.Context) error {
		select {
		case <-time.After(200 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	if err == nil || !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestSandbox_ExecutePanicRecovery(t *testing.T) {
	sb := New(Config{Timeout: 500 * time.Millisecond})

	err := sb.Execute(context.Background(), "panic-plugin", func(ctx context.Context) error {
		panic("fatal unexpected exception")
	})

	if err == nil || !strings.Contains(err.Error(), "plugin panic recovered") {
		t.Fatalf("expected panic recovery error, got %v", err)
	}
}
