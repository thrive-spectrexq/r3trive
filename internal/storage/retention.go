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
	EventsPurged   int64     `json:"events_purged"`
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

	// Check if any events exist before creating files
	initial, err := m.store.QueryEvents(ctx, EventQuery{
		Until: cutoff,
		Limit: 1,
	})
	if err != nil {
		return PurgeStats{}, fmt.Errorf("failed to query aged events: %w", err)
	}

	if len(initial) == 0 {
		return PurgeStats{CutoffTime: cutoff}, nil
	}

	if err := os.MkdirAll(m.archiveDir, 0750); err != nil {
		return PurgeStats{}, fmt.Errorf("failed to create archive directory: %w", err)
	}

	archiveName := fmt.Sprintf("r3trive_archive_%s.jsonl.gz", cutoff.Format("20060102_150405"))
	archivePath := filepath.Clean(filepath.Join(m.archiveDir, archiveName))

	f, err := os.Create(archivePath) // #nosec G304
	if err != nil {
		return PurgeStats{}, fmt.Errorf("failed to create archive file: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	totalArchived := 0
	offset := 0
	chunkSize := 1000

	for {
		events, err := m.store.QueryEvents(ctx, EventQuery{
			Until:  cutoff,
			Limit:  chunkSize,
			Offset: offset,
		})
		if err != nil {
			return PurgeStats{}, fmt.Errorf("failed to query aged events chunk: %w", err)
		}
		if len(events) == 0 {
			break
		}

		for _, evt := range events {
			line, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			if _, err := gz.Write(append(line, '\n')); err != nil {
				return PurgeStats{}, fmt.Errorf("failed to write gzip archive: %w", err)
			}
			totalArchived++
		}

		if len(events) < chunkSize {
			break
		}
		offset += len(events)
	}

	if err := gz.Flush(); err != nil {
		return PurgeStats{}, fmt.Errorf("failed to flush gzip archive: %w", err)
	}

	purged, err := m.store.PruneEvents(ctx, cutoff)
	if err != nil {
		return PurgeStats{}, fmt.Errorf("failed to prune aged events: %w", err)
	}

	return PurgeStats{
		EventsArchived: totalArchived,
		EventsPurged:   purged,
		ArchiveFile:    archivePath,
		CutoffTime:     cutoff,
	}, nil
}

// StartBackgroundWorker runs retention purge cycles periodically until context cancellation.
func (m *RetentionManager) StartBackgroundWorker(ctx context.Context, interval time.Duration) <-chan PurgeStats {
	statsChan := make(chan PurgeStats, 10)
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	go func() {
		defer close(statsChan)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats, err := m.ExecutePurgeCycle(ctx)
				if err == nil && stats.EventsArchived > 0 {
					select {
					case statsChan <- stats:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return statsChan
}
