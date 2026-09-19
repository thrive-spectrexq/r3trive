package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/storage"
)

func TestPostgresStoreNew(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Errorf("expected error for empty DSN")
	}

	store, err := New("postgres://user:pass@localhost:5432/r3trive?sslmode=disable")
	if err != nil {
		t.Fatalf("unexpected initialization error: %v", err)
	}
	if store.DSN() != "postgres://user:pass@localhost:5432/r3trive?sslmode=disable" {
		t.Errorf("DSN mismatch")
	}
	_ = store.Close()
}

func TestPostgresStore_NilDBMethods(t *testing.T) {
	s := &Store{db: nil, dsn: "dummy"}

	ctx := context.Background()

	if err := s.SaveHost(ctx, storage.Host{ID: "h1"}); err == nil || err.Error() == "postgres: SaveHost not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if _, err := s.GetHost(ctx, "h1"); err == nil || err.Error() == "postgres: GetHost not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if _, err := s.ListHosts(ctx); err == nil || err.Error() == "postgres: ListHosts not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if err := s.SaveRule(ctx, storage.StoredRule{ID: "r1"}); err == nil || err.Error() == "postgres: SaveRule not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if _, err := s.GetRule(ctx, "r1"); err == nil || err.Error() == "postgres: GetRule not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if _, err := s.ListRules(ctx, false); err == nil || err.Error() == "postgres: ListRules not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if err := s.DeleteRule(ctx, "r1"); err == nil || err.Error() == "postgres: DeleteRule not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if err := s.SaveIOC(ctx, storage.IOCEntry{ID: "ioc1"}); err == nil || err.Error() == "postgres: SaveIOC not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if _, err := s.QueryIOCs(ctx, "ip", "1.1.1.1"); err == nil || err.Error() == "postgres: QueryIOCs not implemented" {
		t.Errorf("expected connection inactive error, got: %v", err)
	}

	if _, err := s.PruneEvents(ctx, time.Now()); err == nil {
		t.Errorf("expected connection inactive error for PruneEvents, got nil")
	}

	if _, err := s.QueryEvents(ctx, storage.EventQuery{}); err == nil {
		t.Errorf("expected connection inactive error for QueryEvents, got nil")
	}
}

