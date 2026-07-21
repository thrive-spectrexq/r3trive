package ioc

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// IOCType defines the category of an Indicator of Compromise.
type IOCType string

const (
	IOCTypeHash   IOCType = "hash"
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeURL    IOCType = "url"
)

// IOCEntry represents a single indicator of compromise.
type IOCEntry struct {
	ID          string         `json:"id"`
	Type        IOCType        `json:"type"`
	Value       string         `json:"value"`
	Severity    event.Severity `json:"severity"`
	ThreatGroup string         `json:"threat_group,omitempty"`
	Description string         `json:"description,omitempty"`
}

// Match represents a successful IOC hit against an event or artifact.
type Match struct {
	IOC         IOCEntry  `json:"ioc"`
	MatchedOn   string    `json:"matched_on"`
	Timestamp   time.Time `json:"timestamp"`
	EventID     string    `json:"event_id,omitempty"`
	Description string    `json:"description"`
}

// Engine manages in-memory threat intelligence lookup datasets.
type Engine struct {
	mu      sync.RWMutex
	hashes  map[string]IOCEntry
	ips     map[string]IOCEntry
	domains map[string]IOCEntry
	urls    map[string]IOCEntry
}

// NewEngine creates a new IOC Threat Intelligence engine.
func NewEngine() *Engine {
	return &Engine{
		hashes:  make(map[string]IOCEntry),
		ips:     make(map[string]IOCEntry),
		domains: make(map[string]IOCEntry),
		urls:    make(map[string]IOCEntry),
	}
}

// AddEntry registers an indicator into the engine.
func (e *Engine) AddEntry(entry IOCEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()

	val := strings.ToLower(strings.TrimSpace(entry.Value))
	if val == "" {
		return
	}

	switch entry.Type {
	case IOCTypeHash:
		e.hashes[val] = entry
	case IOCTypeIP:
		e.ips[val] = entry
	case IOCTypeDomain:
		e.domains[val] = entry
	case IOCTypeURL:
		e.urls[val] = entry
	default:
		e.hashes[val] = entry
	}
}

// LoadJSONFeed reads IOC entries from a JSON file.
func (e *Engine) LoadJSONFeed(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening feed file: %w", err)
	}
	defer file.Close()

	var entries []IOCEntry
	if err := json.NewDecoder(file).Decode(&entries); err != nil {
		return fmt.Errorf("decoding JSON feed: %w", err)
	}

	for _, entry := range entries {
		e.AddEntry(entry)
	}

	slog.Info("loaded IOC JSON threat feed", "file", filePath, "count", len(entries))
	return nil
}

// LoadCSVFeed reads IOC entries from a CSV file (value,type,severity,description).
func (e *Engine) LoadCSVFeed(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening feed CSV: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	count := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 2 {
			continue
		}

		if strings.ToLower(record[0]) == "value" || strings.ToLower(record[1]) == "type" {
			continue
		}

		value := strings.TrimSpace(record[0])
		iocType := IOCType(strings.ToLower(strings.TrimSpace(record[1])))
		sev := event.SeverityHigh
		if len(record) > 2 && record[2] != "" {
			sev = event.Severity(strings.ToLower(strings.TrimSpace(record[2])))
		}

		desc := ""
		if len(record) > 3 {
			desc = record[3]
		}

		e.AddEntry(IOCEntry{
			ID:          fmt.Sprintf("ioc_%d", count+1),
			Type:        iocType,
			Value:       value,
			Severity:    sev,
			Description: desc,
		})
		count++
	}

	slog.Info("loaded IOC CSV threat feed", "file", filePath, "count", count)
	return nil
}

// MatchEvent checks an event against all active threat intelligence datasets.
func (e *Engine) MatchEvent(evt event.Event) []Match {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []Match

	// Process event hashes
	if evt.Data.Process != nil {
		p := evt.Data.Process
		for _, hashVal := range p.Hashes {
			lowerHash := strings.ToLower(hashVal)
			if entry, ok := e.hashes[lowerHash]; ok {
				matches = append(matches, Match{
					IOC:         entry,
					MatchedOn:   hashVal,
					Timestamp:   evt.Timestamp,
					EventID:     evt.ID,
					Description: fmt.Sprintf("Process hash matched known malicious IOC: %s", entry.Description),
				})
			}
		}
	}

	// File event hashes
	if evt.Data.File != nil {
		f := evt.Data.File
		for _, hashVal := range f.Hashes {
			lowerHash := strings.ToLower(hashVal)
			if entry, ok := e.hashes[lowerHash]; ok {
				matches = append(matches, Match{
					IOC:         entry,
					MatchedOn:   hashVal,
					Timestamp:   evt.Timestamp,
					EventID:     evt.ID,
					Description: fmt.Sprintf("File hash matched known malicious IOC: %s", entry.Description),
				})
			}
		}
	}

	// Network event IPs
	if evt.Data.Network != nil {
		net := evt.Data.Network
		if entry, ok := e.ips[strings.ToLower(net.DstIP)]; ok {
			matches = append(matches, Match{
				IOC:         entry,
				MatchedOn:   net.DstIP,
				Timestamp:   evt.Timestamp,
				EventID:     evt.ID,
				Description: fmt.Sprintf("Destination IP matched known C2 / Malicious IP: %s", entry.Description),
			})
		}
	}

	return matches
}

// Count returns the total number of loaded IOCs across all categories.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.hashes) + len(e.ips) + len(e.domains) + len(e.urls)
}
