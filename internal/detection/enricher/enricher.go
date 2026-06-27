// Package enricher adds contextual data to events — hashes, parent process
// resolution, user info, and GeoIP lookups.
package enricher

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Enricher adds context to events passing through the pipeline.
type Enricher struct {
	// geoIPPath is the path to a GeoIP database (Phase 2).
	geoIPPath string
}

// New creates a new Enricher.
func New() *Enricher {
	return &Enricher{}
}

// Enrich adds contextual information to an event.
func (e *Enricher) Enrich(evt event.Event) event.Event {
	if evt.Enrichments == nil {
		evt.Enrichments = make(map[string]any)
	}

	// Enrich process events with file hashes
	if evt.Data.Process != nil && evt.Data.Process.Path != "" {
		if hashes := hashFile(evt.Data.Process.Path); hashes != nil {
			if evt.Data.Process.Hashes == nil {
				evt.Data.Process.Hashes = make(map[string]string)
			}
			for k, v := range hashes {
				evt.Data.Process.Hashes[k] = v
			}
		}
	}

	// Enrich file events with hashes
	if evt.Data.File != nil && evt.Data.File.Path != "" {
		if hashes := hashFile(evt.Data.File.Path); hashes != nil {
			if evt.Data.File.Hashes == nil {
				evt.Data.File.Hashes = make(map[string]string)
			}
			for k, v := range hashes {
				evt.Data.File.Hashes[k] = v
			}
		}
	}

	return evt
}

// hashFile computes SHA256 of a file. Returns nil if the file can't be read.
func hashFile(path string) map[string]string {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		slog.Debug("enricher: could not hash file", "path", path, "error", err)
		return nil
	}

	hash := sha256.Sum256(data)
	return map[string]string{
		"sha256": fmt.Sprintf("%x", hash),
	}
}
