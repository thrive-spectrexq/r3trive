package enricher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestEnricher_EnrichProcessAndFile(t *testing.T) {
	tempDir := t.TempDir()
	binFile := filepath.Join(tempDir, "sample.bin")
	data := []byte("malicious or benign payload content")
	if err := os.WriteFile(binFile, data, 0o600); err != nil {
		t.Fatalf("failed writing temp file: %v", err)
	}

	e := New()

	// 1. Process event enrichment
	procEvt := event.Event{
		ID:   "evt-proc",
		Type: event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:  100,
				Path: binFile,
			},
		},
	}

	enrichedProc := e.Enrich(procEvt)
	if enrichedProc.Data.Process.Hashes == nil || enrichedProc.Data.Process.Hashes["sha256"] == "" {
		t.Errorf("expected process sha256 hash to be computed, got %+v", enrichedProc.Data.Process.Hashes)
	}

	// 2. File event enrichment
	fileEvt := event.Event{
		ID:   "evt-file",
		Type: event.FileCreate,
		Data: event.EventData{
			File: &event.FileData{
				Path: binFile,
			},
		},
	}

	enrichedFile := e.Enrich(fileEvt)
	if enrichedFile.Data.File.Hashes == nil || enrichedFile.Data.File.Hashes["sha256"] == "" {
		t.Errorf("expected file sha256 hash to be computed, got %+v", enrichedFile.Data.File.Hashes)
	}

	// 3. Non-existent file path handling
	missingEvt := event.Event{
		ID:   "evt-missing",
		Type: event.FileCreate,
		Data: event.EventData{
			File: &event.FileData{
				Path: filepath.Join(tempDir, "non_existent.bin"),
			},
		},
	}
	enrichedMissing := e.Enrich(missingEvt)
	if enrichedMissing.Data.File.Hashes != nil {
		t.Errorf("expected nil hashes for non-existent file, got %+v", enrichedMissing.Data.File.Hashes)
	}
}
