package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ComputeFileChecksum computes the SHA256 hex digest of a file.
func ComputeFileChecksum(filePath string) (string, error) {
	cleanPath := filepath.Clean(filePath)
	f, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", cleanPath, err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("failed to hash file %s: %w", cleanPath, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyFileChecksum checks whether the SHA256 hash of a file matches the expected hex string.
func VerifyFileChecksum(filePath string, expectedHash string) (bool, error) {
	computed, err := ComputeFileChecksum(filePath)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(computed, expectedHash), nil
}

// VerifyDirectoryChecksums verifies a map of relative file paths to expected SHA256 hashes.
// It returns a list of mismatched or missing file paths.
func VerifyDirectoryChecksums(baseDir string, expectedHashes map[string]string) ([]string, error) {
	var mismatches []string

	for relPath, expected := range expectedHashes {
		fullPath := filepath.Join(baseDir, relPath)
		match, err := VerifyFileChecksum(fullPath, expected)
		if err != nil || !match {
			mismatches = append(mismatches, relPath)
		}
	}

	return mismatches, nil
}
