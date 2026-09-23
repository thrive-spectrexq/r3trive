package ioc

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/netip"
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

type cidrEntry struct {
	prefix netip.Prefix
	entry  IOCEntry
}

// bloomFilter provides a fast, zero-allocation probabilistic pre-filter for hashes.
type bloomFilter struct {
	bits [8192]uint64 // 64 KB bitset (524,288 bits)
}

func (bf *bloomFilter) add(item string) {
	h1, h2 := hashPair(item)
	bf.bits[(h1%524288)/64] |= 1 << (h1 % 64)
	bf.bits[(h2%524288)/64] |= 1 << (h2 % 64)
}

func (bf *bloomFilter) mayContain(item string) bool {
	h1, h2 := hashPair(item)
	b1 := bf.bits[(h1%524288)/64]&(1<<(h1%64)) != 0
	b2 := bf.bits[(h2%524288)/64]&(1<<(h2%64)) != 0
	return b1 && b2
}

func hashPair(s string) (uint64, uint64) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	h1 := h.Sum64()
	h2 := (h1 >> 32) | (h1 << 32) ^ 0x5bd1e9955bd1e995
	return h1, h2
}

// Engine manages in-memory threat intelligence lookup datasets.
type Engine struct {
	mu         sync.RWMutex
	hashes     map[string]IOCEntry
	ips        map[string]IOCEntry
	cidrs      []cidrEntry
	domains    map[string]IOCEntry
	urls       map[string]IOCEntry
	hashFilter bloomFilter
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
		e.hashFilter.add(val)
	case IOCTypeIP:
		e.ips[val] = entry
		if strings.Contains(val, "/") {
			if prefix, err := netip.ParsePrefix(val); err == nil {
				e.cidrs = append(e.cidrs, cidrEntry{prefix: prefix, entry: entry})
			}
		}
	case IOCTypeDomain:
		e.domains[val] = entry
	case IOCTypeURL:
		e.urls[val] = entry
	default:
		e.hashes[val] = entry
		e.hashFilter.add(val)
	}
}

// LoadJSONFeed reads IOC entries from a JSON file.
func (e *Engine) LoadJSONFeed(filePath string) error {
	file, err := os.Open(filePath) // #nosec G304
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
	file, err := os.Open(filePath) // #nosec G304
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

	// Process event hashes (guarded by bloom filter)
	if evt.Data.Process != nil {
		p := evt.Data.Process
		for _, hashVal := range p.Hashes {
			lowerHash := strings.ToLower(hashVal)
			if e.hashFilter.mayContain(lowerHash) {
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

		// Inspect process command line for malicious domains and URLs
		if p.CmdLine != "" {
			cmdLower := strings.ToLower(p.CmdLine)
			for dVal, entry := range e.domains {
				if strings.Contains(cmdLower, dVal) {
					matches = append(matches, Match{
						IOC:         entry,
						MatchedOn:   dVal,
						Timestamp:   evt.Timestamp,
						EventID:     evt.ID,
						Description: fmt.Sprintf("Process command line contains malicious domain: %s", entry.Description),
					})
				}
			}
			for uVal, entry := range e.urls {
				if strings.Contains(cmdLower, uVal) {
					matches = append(matches, Match{
						IOC:         entry,
						MatchedOn:   uVal,
						Timestamp:   evt.Timestamp,
						EventID:     evt.ID,
						Description: fmt.Sprintf("Process command line contains malicious URL: %s", entry.Description),
					})
				}
			}
		}
	}

	// File event hashes (guarded by bloom filter)
	if evt.Data.File != nil {
		f := evt.Data.File
		for _, hashVal := range f.Hashes {
			lowerHash := strings.ToLower(hashVal)
			if e.hashFilter.mayContain(lowerHash) {
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
	}

	// Network event IPs and Subnets
	if evt.Data.Network != nil {
		netData := evt.Data.Network
		lowerIP := strings.ToLower(strings.TrimSpace(netData.DstIP))
		if lowerIP != "" {
			// Exact IP match
			if entry, ok := e.ips[lowerIP]; ok {
				matches = append(matches, Match{
					IOC:         entry,
					MatchedOn:   netData.DstIP,
					Timestamp:   evt.Timestamp,
					EventID:     evt.ID,
					Description: fmt.Sprintf("Destination IP matched known C2 / Malicious IP: %s", entry.Description),
				})
			} else if addr, err := netip.ParseAddr(lowerIP); err == nil {
				// CIDR Subnet match
				for _, c := range e.cidrs {
					if c.prefix.Contains(addr) {
						matches = append(matches, Match{
							IOC:         c.entry,
							MatchedOn:   netData.DstIP,
							Timestamp:   evt.Timestamp,
							EventID:     evt.ID,
							Description: fmt.Sprintf("Destination IP matched malicious subnet %s: %s", c.prefix, c.entry.Description),
						})
						break
					}
				}
			}

			// Destination domain match
			if entry, ok := e.domains[lowerIP]; ok {
				matches = append(matches, Match{
					IOC:         entry,
					MatchedOn:   netData.DstIP,
					Timestamp:   evt.Timestamp,
					EventID:     evt.ID,
					Description: fmt.Sprintf("Destination matched known malicious domain: %s", entry.Description),
				})
			}
		}
	}

	// Check enrichments for domain/URL indicators
	if evt.Enrichments != nil {
		if domainVal, ok := evt.Enrichments["domain"].(string); ok && domainVal != "" {
			if entry, ok := e.domains[strings.ToLower(domainVal)]; ok {
				matches = append(matches, Match{
					IOC:         entry,
					MatchedOn:   domainVal,
					Timestamp:   evt.Timestamp,
					EventID:     evt.ID,
					Description: fmt.Sprintf("Enriched domain matched malicious IOC: %s", entry.Description),
				})
			}
		}
		if urlVal, ok := evt.Enrichments["url"].(string); ok && urlVal != "" {
			if entry, ok := e.urls[strings.ToLower(urlVal)]; ok {
				matches = append(matches, Match{
					IOC:         entry,
					MatchedOn:   urlVal,
					Timestamp:   evt.Timestamp,
					EventID:     evt.ID,
					Description: fmt.Sprintf("Enriched URL matched malicious IOC: %s", entry.Description),
				})
			}
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
