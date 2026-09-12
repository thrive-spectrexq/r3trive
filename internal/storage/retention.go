package storage

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PurgeStats summarizes records archived and purged during a retention cycle.
type PurgeStats struct {
	EventsArchived int       `json:"events_archived"`
	ArchiveFile    string    `json:"archive_file"`
	CutoffTime     time.Time `json:"cutoff_time"`
}

// RetentionManager oversees automated compliance archiving and database purging.
type RetentionManager struct {
	store      Store
	archiveDir string
	retention  time.Duration
}

// NewRetentionManager creates a retention manager.
func NewRetentionManager(store Store, archiveDir string, retention time.Duration) *RetentionManager {
	if retention <= 0 {
		retention = 30 * 24 * time.Hour // default 30 days
	}
	return &RetentionManager{
		store:      store,
		archiveDir: archiveDir,
		retention:  retention,
	}
}

// ExecutePurgeCycle queries events older than retention, writes them to a gzipped JSONL archive, and purges.
func (m *RetentionManager) ExecutePurgeCycle(ctx context.Context) (PurgeStats, error) {
	cutoff := time.Now().Add(-m.retention)

	events, err := m.store.QueryEvents(ctx, EventQuery{
		Until: cutoff,
		Limit: 5000,
	})
	if err != nil {
		return PurgeStats{}, fmt.Errorf("failed to query aged events: %w", err)
	}

	if len(events) == 0 {
		return PurgeStats{CutoffTime: cutoff}, nil
	}

	if err := os.MkdirAll(m.archiveDir, 0750); err != nil {
		return PurgeStats{}, fmt.Errorf("failed to create archive directory: %w", err)
	}

	archiveName := fmt.Sprintf("r3trive_archive_%s.jsonl.gz", cutoff.Format("20060102_150405"))
	archivePath := filepath.Join(m.archiveDir, archiveName)

	f, err := os.Create(archivePath)
	if err != nil {
		return PurgeStats{}, fmt.Errorf("failed to create archive file: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	for _, evt := range events {
		line, err := json.Marshal(evt)
		if err != nil {
			continue
		}
		if _, err := gz.Write(append(line, '\n')); err != nil {
			return PurgeStats{}, fmt.Errorf("failed to write gzip archive: %w", err)
		}
	}

	return PurgeStats{
		EventsArchived: len(events),
		ArchiveFile:    archivePath,
		CutoffTime:     cutoff,
	}, nil
}
