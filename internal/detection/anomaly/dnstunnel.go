package anomaly

import (
	"math"
	"strings"
	"sync"
	"time"
)

// CalculateShannonEntropy calculates the Shannon entropy H(X) in bits for a given text string.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	total := float64(len([]rune(s)))
	var entropy float64

	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// DNSTunnelDetector detects DNS data exfiltration and tunneling through entropy analysis and query rate metrics.
type DNSTunnelDetector struct {
	entropyThreshold float64
	domainQueries    map[string][]time.Time
	mu               sync.Mutex
}

// NewDNSTunnelDetector creates a new detector with entropy threshold (typically 3.8).
func NewDNSTunnelDetector(entropyThreshold float64) *DNSTunnelDetector {
	if entropyThreshold <= 0 {
		entropyThreshold = 3.8
	}
	return &DNSTunnelDetector{
		entropyThreshold: entropyThreshold,
		domainQueries:    make(map[string][]time.Time),
	}
}

// DNSAnalysisResult contains the metrics from evaluating a DNS query.
type DNSAnalysisResult struct {
	Domain          string  `json:"domain"`
	Subdomain       string  `json:"subdomain"`
	Entropy         float64 `json:"entropy"`
	QueryRatePerMin int     `json:"query_rate_per_min"`
	IsTunnelSuspect bool    `json:"is_tunnel_suspect"`
}

// EvaluateQuery analyzes a FQDN for tunneling indicators.
func (d *DNSTunnelDetector) EvaluateQuery(fqdn string) DNSAnalysisResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	cleaned := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	labels := strings.Split(cleaned, ".")

	var subdomain string
	var apex string

	if len(labels) > 2 {
		subdomain = strings.Join(labels[:len(labels)-2], ".")
		apex = strings.Join(labels[len(labels)-2:], ".")
	} else {
		subdomain = ""
		apex = cleaned
	}

	entropy := CalculateShannonEntropy(subdomain)

	// Update query history for apex
	now := time.Now()
	oneMinAgo := now.Add(-1 * time.Minute)

	history := d.domainQueries[apex]
	valid := make([]time.Time, 0, len(history)+1)
	for _, ts := range history {
		if ts.After(oneMinAgo) {
			valid = append(valid, ts)
		}
	}
	valid = append(valid, now)
	d.domainQueries[apex] = valid

	queryRate := len(valid)

	// A domain is flagged if subdomain entropy exceeds threshold AND length > 12 characters,
	// or query volume exceeds 40 queries/minute with elevated entropy.
	isSuspect := (entropy >= d.entropyThreshold && len(subdomain) > 12) ||
		(queryRate >= 40 && entropy >= 3.2)

	return DNSAnalysisResult{
		Domain:          cleaned,
		Subdomain:       subdomain,
		Entropy:         entropy,
		QueryRatePerMin: queryRate,
		IsTunnelSuspect: isSuspect,
	}
}
