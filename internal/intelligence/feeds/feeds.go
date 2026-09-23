package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/intelligence/ioc"
	"github.com/thrive-spectrexq/r3trive/internal/storage"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// FeedSource represents a remote threat intelligence source.
type FeedSource struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	URL      string        `json:"url"`
	Format   string        `json:"format"` // json, csv
	Interval time.Duration `json:"interval"`
	Disabled bool          `json:"disabled"`
}

// Manager coordinates fetching and ingesting remote threat feeds.
type Manager struct {
	iocEngine  *ioc.Engine
	store      storage.Store
	httpClient *http.Client
	sources    []FeedSource
}

// NewManager creates a new Feed Manager instance.
func NewManager(iocEngine *ioc.Engine) *Manager {
	return &Manager{
		iocEngine: iocEngine,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		sources: make([]FeedSource, 0),
	}
}

// SetStore attaches a persistent storage backend to the feed manager.
func (m *Manager) SetStore(store storage.Store) {
	m.store = store
}

// RegisterSource adds a feed source to the manager.
func (m *Manager) RegisterSource(src FeedSource) {
	m.sources = append(m.sources, src)
}

// FetchSource retrieves and parses IOC entries from a single FeedSource.
func (m *Manager) FetchSource(ctx context.Context, src FeedSource) (int, error) {
	if src.Disabled || src.URL == "" {
		return 0, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetching feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("feed server returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading feed body: %w", err)
	}

	var entries []ioc.IOCEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return 0, fmt.Errorf("unmarshalling JSON feed: %w", err)
	}

	for _, entry := range entries {
		m.iocEngine.AddEntry(entry)
		if m.store != nil {
			_ = m.store.SaveIOC(ctx, storage.IOCEntry{
				ID:        entry.ID,
				Type:      string(entry.Type),
				Value:     entry.Value,
				Source:    src.Name,
				Severity:  string(entry.Severity),
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	slog.Info("successfully ingested threat feed", "source", src.Name, "count", len(entries))
	return len(entries), nil
}

// LoadFromStore warms the in-memory IOC engine from persistent storage.
func (m *Manager) LoadFromStore(ctx context.Context) (int, error) {
	if m.store == nil {
		return 0, nil
	}

	iocs, err := m.store.QueryIOCs(ctx, "", "")
	if err != nil {
		return 0, fmt.Errorf("loading IOCs from store: %w", err)
	}

	for _, stored := range iocs {
		m.iocEngine.AddEntry(ioc.IOCEntry{
			ID:          stored.ID,
			Type:        ioc.IOCType(stored.Type),
			Value:       stored.Value,
			Severity:    event.Severity(stored.Severity),
			Description: fmt.Sprintf("Persisted IOC from %s", stored.Source),
		})
	}

	slog.Info("warmed IOC engine from database", "count", len(iocs))
	return len(iocs), nil
}
