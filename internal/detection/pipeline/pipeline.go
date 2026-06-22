// Package pipeline orchestrates the event processing flow:
// Sensors → Normalizer → Enricher → Ring Buffer → (Rules, Correlation, Storage)
package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
	"github.com/thrive-spectrexq/r3trive/pkg/utils"
)

// Config holds pipeline configuration.
type Config struct {
	Sensors        []sensor.Sensor
	Store          storage.Store
	YaraScanner    yara.Scanner
	RingBufferSize int
	BatchSize      int
	FlushInterval  time.Duration
}

// EventCallback is a function invoked for each event passing through the pipeline.
type EventCallback func(event.Event)

// Pipeline orchestrates event collection, processing, and storage.
type Pipeline struct {
	cfg       Config
	ring      *utils.RingBuffer[event.Event]
	callbacks []EventCallback
	mu        sync.RWMutex
}

// New creates a new event pipeline.
func New(cfg Config) *Pipeline {
	if cfg.RingBufferSize == 0 {
		cfg.RingBufferSize = 10000
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = time.Second
	}

	return &Pipeline{
		cfg:  cfg,
		ring: utils.NewRingBuffer[event.Event](cfg.RingBufferSize),
	}
}

// OnEvent registers a callback that will be invoked for every event.
func (p *Pipeline) OnEvent(fn EventCallback) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callbacks = append(p.callbacks, fn)
}

// Start runs the pipeline. It blocks until the context is cancelled.
func (p *Pipeline) Start(ctx context.Context) error {
	// Event channel shared by all sensors
	eventCh := make(chan event.Event, 1000)

	// Start all sensors
	var wg sync.WaitGroup
	for _, s := range p.cfg.Sensors {
		wg.Add(1)
		go func(s sensor.Sensor) {
			defer wg.Done()
			slog.Info("starting sensor", "sensor", s.Name())
			if err := s.Start(ctx, eventCh); err != nil {
				slog.Error("sensor error", "sensor", s.Name(), "error", err)
			}
		}(s)
	}

	// Storage batch writer
	var storageWg sync.WaitGroup
	batchCh := make(chan event.Event, p.cfg.BatchSize*2)

	if p.cfg.Store != nil {
		storageWg.Add(1)
		go func() {
			defer storageWg.Done()
			p.batchWriter(ctx, batchCh)
		}()
	}

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			slog.Info("pipeline shutting down, waiting for sensors")
			wg.Wait()
			close(batchCh)
			storageWg.Wait()
			slog.Info("pipeline stopped")
			return nil

		case evt := <-eventCh:
			// Trigger YARA on certain events
			if p.cfg.YaraScanner != nil {
				if evt.Type == "FileCreate" && evt.Data.File != nil {
					path := evt.Data.File.Path
					if path != "" {
						go func(path string, evtID string) {
							matches, err := p.cfg.YaraScanner.ScanFile(ctx, path)
							if err != nil {
								slog.Error("yara scan failed", "path", path, "error", err)
								return
							}
							if len(matches) > 0 {
								slog.Warn("yara matched on file creation", "path", path, "matches", len(matches))
							}
						}(path, evt.ID)
					}
				} else if evt.Type == "ProcessCreate" && evt.Data.Process != nil {
					path := evt.Data.Process.Name // Or ImagePath if available in your struct
					if path != "" {
						go func(path string, evtID string) {
							matches, err := p.cfg.YaraScanner.ScanFile(ctx, path)
							if err != nil {
								slog.Error("yara scan failed", "path", path, "error", err)
								return
							}
							if len(matches) > 0 {
								slog.Warn("yara matched on process creation", "path", path, "matches", len(matches))
							}
						}(path, evt.ID)
					}
				}
			}

			// Add to ring buffer
			p.ring.Push(evt)

			// Notify callbacks
			p.mu.RLock()
			for _, cb := range p.callbacks {
				cb(evt)
			}
			p.mu.RUnlock()

			// Forward to storage
			if p.cfg.Store != nil {
				select {
				case batchCh <- evt:
				default:
					slog.Warn("storage batch channel full, dropping event",
						"event_id", evt.ID)
				}
			}
		}
	}
}

// batchWriter batches events and writes them to storage.
func (p *Pipeline) batchWriter(ctx context.Context, ch <-chan event.Event) {
	batch := make([]event.Event, 0, p.cfg.BatchSize)
	ticker := time.NewTicker(p.cfg.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := p.cfg.Store.SaveEvents(ctx, batch); err != nil {
			slog.Error("batch write failed", "count", len(batch), "error", err)
		} else {
			slog.Debug("batch written", "count", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, evt)
			if len(batch) >= p.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Stats returns current pipeline statistics.
func (p *Pipeline) Stats() PipelineStats {
	return PipelineStats{
		RingBufferLen: p.ring.Len(),
		RingBufferCap: p.ring.Cap(),
		SensorCount:   len(p.cfg.Sensors),
	}
}

// PipelineStats holds runtime statistics.
type PipelineStats struct {
	RingBufferLen int `json:"ring_buffer_len"`
	RingBufferCap int `json:"ring_buffer_cap"`
	SensorCount   int `json:"sensor_count"`
}
