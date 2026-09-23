// Package pipeline orchestrates the event processing flow:
// Sensors → Normalizer → Enricher → Ring Buffer → (Rules, Correlation, Storage)
package pipeline

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/detection/enricher"
	"github.com/thrive-spectrexq/r3trive/internal/detection/normalizer"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/internal/detection/yara"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/internal/telemetry"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
	"github.com/thrive-spectrexq/r3trive/pkg/utils"
)

// Config holds pipeline configuration.
type Config struct {
	Sensors        []sensor.Sensor
	Store          storage.Store
	YaraScanner    yara.Scanner
	Normalizer     *normalizer.Normalizer
	Enricher       *enricher.Enricher
	RingBufferSize int
	BatchSize      int
	FlushInterval  time.Duration
}

// EventCallback is a function invoked for each event passing through the pipeline.
type EventCallback func(event.Event)

// Pipeline orchestrates event collection, processing, and storage.
type Pipeline struct {
	cfg        Config
	normalizer *normalizer.Normalizer
	enricher   *enricher.Enricher
	ring       *utils.RingBuffer[event.Event]
	callbacks  []EventCallback
	mu         sync.RWMutex
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

	norm := cfg.Normalizer
	if norm == nil {
		norm = normalizer.New()
	}

	enr := cfg.Enricher
	if enr == nil {
		enr = enricher.New()
	}

	return &Pipeline{
		cfg:        cfg,
		normalizer: norm,
		enricher:   enr,
		ring:       utils.NewRingBuffer[event.Event](cfg.RingBufferSize),
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

	// Bounded worker pool for YARA scanning to prevent goroutine exhaustion and disk thrashing
	type yaraJob struct {
		path  string
		evtID string
	}
	numWorkers := runtime.NumCPU() * 2
	if numWorkers < 4 {
		numWorkers = 4
	}
	yaraJobCh := make(chan yaraJob, 256)
	var yaraWg sync.WaitGroup
	if p.cfg.YaraScanner != nil {
		for i := 0; i < numWorkers; i++ {
			yaraWg.Add(1)
			go func() {
				defer yaraWg.Done()
				for job := range yaraJobCh {
					matches, err := p.cfg.YaraScanner.ScanFile(ctx, job.path)
					if err != nil {
						slog.Debug("yara scan failed", "path", job.path, "error", err)
						continue
					}
					if len(matches) > 0 {
						slog.Warn("yara matched on file/process", "path", job.path, "matches", len(matches), "event_id", job.evtID)
					}
				}
			}()
		}
	}

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			slog.Info("pipeline shutting down, waiting for sensors")
			wg.Wait()
			close(batchCh)
			storageWg.Wait()
			if p.cfg.YaraScanner != nil {
				close(yaraJobCh)
				yaraWg.Wait()
			}
			slog.Info("pipeline stopped")
			return nil

		case evt := <-eventCh:
			start := time.Now()

			// Normalization & Enrichment Stage
			if p.normalizer != nil {
				evt = p.normalizer.Normalize(evt)
			}
			if p.enricher != nil {
				evt = p.enricher.Enrich(evt)
			}

			telemetry.RecordEvent(ctx, 1)
			telemetry.RecordDetectionLatency(ctx, float64(time.Since(start).Milliseconds()))

			// Trigger YARA on file and process events (supporting canonical and legacy types)
			if p.cfg.YaraScanner != nil {
				var scanPath string
				if (evt.Type == event.FileCreate || evt.Type == "FileCreate") && evt.Data.File != nil {
					scanPath = evt.Data.File.Path
				} else if (evt.Type == event.ProcessCreate || evt.Type == "ProcessCreate") && evt.Data.Process != nil {
					if evt.Data.Process.Path != "" {
						scanPath = evt.Data.Process.Path
					} else {
						scanPath = evt.Data.Process.Name
					}
				}

				if scanPath != "" {
					select {
					case yaraJobCh <- yaraJob{path: scanPath, evtID: evt.ID}:
					default:
						slog.Warn("yara worker pool full, skipping non-blocking scan", "path", scanPath)
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
