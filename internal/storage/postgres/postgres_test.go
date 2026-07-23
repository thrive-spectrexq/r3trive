package postgres

import (
	"testing"
)

func TestPostgresStore_UnsupportedError(t *testing.T) {
	_, err := New("postgres://user:pass@localhost:5432/r3trive")
	if err == nil {
		t.Fatal("expected error when initializing postgres store, got nil")
	}
}
