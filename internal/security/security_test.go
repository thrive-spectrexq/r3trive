package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWipe(t *testing.T) {
	secret := []byte("super_secret_api_key_12345")
	Wipe(secret)

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte at index %d was not zeroed: %d", i, b)
		}
	}

	// Ensure Wipe on empty buffer does not panic
	Wipe(nil)
	Wipe([]byte{})
}

func TestMemoryLocking(t *testing.T) {
	buf := make([]byte, 4096)
	copy(buf, []byte("sensitive_encryption_key_material"))

	// Empty buffer should return error
	if err := LockBuffer(nil); !errors.Is(err, ErrEmptyBuffer) {
		t.Fatalf("expected ErrEmptyBuffer on nil, got: %v", err)
	}

	// Lock memory buffer (on Windows VirtualLock may succeed or fail with quota, test handles gracefully)
	err := LockBuffer(buf)
	if err == nil {
		defer UnlockBuffer(buf)
	}

	// Unlock empty buffer should be safe
	if err := UnlockBuffer(nil); err != nil {
		t.Fatalf("unexpected error unlocking nil buffer: %v", err)
	}
}

func TestChecksumVerification(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.conf")
	content := []byte("r3trive_config_payload_content")

	if err := os.WriteFile(testFile, content, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, err := ComputeFileChecksum(testFile)
	if err != nil {
		t.Fatalf("failed to compute checksum: %v", err)
	}

	if len(hash) != 64 {
		t.Fatalf("expected 64 char hex hash, got: %s", hash)
	}

	matched, err := VerifyFileChecksum(testFile, hash)
	if err != nil || !matched {
		t.Fatalf("expected matching checksum, got matched=%v, err=%v", matched, err)
	}

	wrongMatch, _ := VerifyFileChecksum(testFile, "0000000000000000000000000000000000000000000000000000000000000000")
	if wrongMatch {
		t.Fatalf("expected non-match for bogus hash")
	}

	// Directory checksum check
	expectedMap := map[string]string{
		"test.conf": hash,
	}
	mismatches, err := VerifyDirectoryChecksums(tmpDir, expectedMap)
	if err != nil || len(mismatches) > 0 {
		t.Fatalf("expected no mismatches, got %v (err: %v)", mismatches, err)
	}
}
