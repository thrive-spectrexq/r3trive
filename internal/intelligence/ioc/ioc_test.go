package ioc

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestIOCEngine(t *testing.T) {
	eng := NewEngine()

	eng.AddEntry(IOCEntry{
		ID:          "ioc-1",
		Type:        IOCTypeIP,
		Value:       "185.220.101.47",
		Severity:    event.SeverityCritical,
		Description: "Known Tor exit node / C2 server",
	})

	if eng.Count() != 1 {
		t.Fatalf("expected count 1, got %d", eng.Count())
	}

	evt := event.Event{
		ID:        "evt-123",
		Timestamp: time.Now().UTC(),
		Type:      event.NetworkConnect,
		Data: event.EventData{
			Network: &event.NetworkData{
				DstIP:   "185.220.101.47",
				DstPort: 443,
			},
		},
	}

	matches := eng.MatchEvent(evt)
	if len(matches) == 0 {
		t.Fatalf("expected 1 IOC match, got 0")
	}

	if matches[0].MatchedOn != "185.220.101.47" {
		t.Errorf("expected match on IP 185.220.101.47, got %s", matches[0].MatchedOn)
	}
}

func TestCSVFeedLoading(t *testing.T) {
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "feed.csv")

	csvContent := `value,type,severity,description
192.168.1.100,ip,high,Suspicious internal scanner
eicar_hash_sample,hash,critical,EICAR Hash
`
	if err := os.WriteFile(csvPath, []byte(csvContent), 0600); err != nil {
		t.Fatalf("write csv error: %v", err)
	}

	eng := NewEngine()
	if err := eng.LoadCSVFeed(csvPath); err != nil {
		t.Fatalf("LoadCSVFeed error: %v", err)
	}

	if eng.Count() != 2 {
		t.Errorf("expected 2 loaded entries, got %d", eng.Count())
	}
}

func TestCIDRAndDomainURLMatching(t *testing.T) {
	eng := NewEngine()

	// Add CIDR subnet
	eng.AddEntry(IOCEntry{
		ID:          "ioc-subnet",
		Type:        IOCTypeIP,
		Value:       "198.51.100.0/24",
		Severity:    event.SeverityCritical,
		Description: "Malicious Russian C2 Subnet",
	})

	// Add domain
	eng.AddEntry(IOCEntry{
		ID:          "ioc-domain",
		Type:        IOCTypeDomain,
		Value:       "c2-evil-domain.com",
		Severity:    event.SeverityHigh,
		Description: "Known adversary beacon domain",
	})

	// Add URL
	eng.AddEntry(IOCEntry{
		ID:          "ioc-url",
		Type:        IOCTypeURL,
		Value:       "http://malicious-drop.com/payload.bin",
		Severity:    event.SeverityCritical,
		Description: "Stage 2 loader payload URL",
	})

	// 1. Test IP in CIDR subnet
	evtSubnet := event.Event{
		ID:        "evt-sub-1",
		Timestamp: time.Now().UTC(),
		Type:      event.NetworkConnect,
		Data: event.EventData{
			Network: &event.NetworkData{
				DstIP: "198.51.100.45",
			},
		},
	}
	matchesSub := eng.MatchEvent(evtSubnet)
	if len(matchesSub) == 0 {
		t.Fatalf("expected CIDR match for 198.51.100.45 in 198.51.100.0/24")
	}

	// 2. Test domain in process command line
	evtCmd := event.Event{
		ID:        "evt-cmd-1",
		Timestamp: time.Now().UTC(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				Name:    "powershell.exe",
				CmdLine: "curl -Uri http://c2-evil-domain.com/beacon",
			},
		},
	}
	matchesCmd := eng.MatchEvent(evtCmd)
	if len(matchesCmd) == 0 {
		t.Fatalf("expected domain match in process command line")
	}

	// 3. Test enriched URL match
	evtURL := event.Event{
		ID:          "evt-url-1",
		Timestamp:   time.Now().UTC(),
		Type:        event.NetworkConnect,
		Enrichments: map[string]any{"url": "http://malicious-drop.com/payload.bin"},
	}
	matchesURL := eng.MatchEvent(evtURL)
	if len(matchesURL) == 0 {
		t.Fatalf("expected URL match in enrichments")
	}
}
