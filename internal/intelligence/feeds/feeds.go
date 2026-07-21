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
	}

	slog.Info("successfully ingested threat feed", "source", src.Name, "count", len(entries))
	return len(entries), nil
}
