package anomaly

import (
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CalculateByteEntropy calculates Shannon entropy for raw byte slices (0.0 to 8.0 bits).
func CalculateByteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := [256]int{}
	for _, b := range data {
		freq[b]++
	}

	total := float64(len(data))
	var entropy float64

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// FileMutationRecord captures an observed file change made by a process.
type FileMutationRecord struct {
	Path      string
	Timestamp time.Time
	Entropy   float64
	IsRename  bool
}

// RansomwareDetector observes process filesystem IO and identifies mass-encryption patterns.
type RansomwareDetector struct {
	processActivity map[int][]FileMutationRecord // pid -> mutations
	windowDuration  time.Duration
	mutationCount   int
	entropyLimit    float64
	mu              sync.Mutex
}

// NewRansomwareDetector creates a ransomware behavioral heuristic detector.
func NewRansomwareDetector(window time.Duration, mutationThreshold int, minEntropy float64) *RansomwareDetector {
	if window <= 0 {
		window = 5 * time.Second
	}
	if mutationThreshold <= 0 {
		mutationThreshold = 15
	}
	if minEntropy <= 0 {
		minEntropy = 7.2
	}
	return &RansomwareDetector{
		processActivity: make(map[int][]FileMutationRecord),
		windowDuration:  window,
		mutationCount:   mutationThreshold,
		entropyLimit:    minEntropy,
	}
}

// RansomwareAlert contains diagnostic findings when ransomware behavior is detected.
type RansomwareAlert struct {
	PID            int      `json:"pid"`
	FileCount      int      `json:"file_count"`
	AverageEntropy float64  `json:"avg_entropy"`
	SuspiciousExts []string `json:"suspicious_extensions"`
	IsRansomware   bool     `json:"is_ransomware"`
}

var knownRansomwareExts = map[string]bool{
	".locked":    true,
	".crypto":    true,
	".enc":       true,
	".lockbit":   true,
	".blackcat":  true,
	".crypted":   true,
	".wnry":      true,
}

// RecordMutation logs a file modification event for a process and evaluates whether it breaches ransomware heuristics.
func (r *RansomwareDetector) RecordMutation(pid int, path string, dataSample []byte, isRename bool) RansomwareAlert {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.windowDuration)

	entropy := 0.0
	if len(dataSample) > 0 {
		entropy = CalculateByteEntropy(dataSample)
	}

	record := FileMutationRecord{
		Path:      path,
		Timestamp: now,
		Entropy:   entropy,
		IsRename:  isRename,
	}

	// Purge aged entries for this PID
	history := r.processActivity[pid]
	active := make([]FileMutationRecord, 0, len(history)+1)
	for _, rec := range history {
		if rec.Timestamp.After(cutoff) {
			active = append(active, rec)
		}
	}
	active = append(active, record)
	r.processActivity[pid] = active

	// Check metrics
	count := len(active)
	if count < r.mutationCount {
		return RansomwareAlert{PID: pid, FileCount: count}
	}

	var totalEntropy float64
	var entropySamples int
	extSet := make(map[string]bool)

	for _, rec := range active {
		if rec.Entropy > 0 {
			totalEntropy += rec.Entropy
			entropySamples++
		}
		ext := strings.ToLower(filepath.Ext(rec.Path))
		if ext != "" {
			extSet[ext] = true
		}
	}

	avgEntropy := 0.0
	if entropySamples > 0 {
		avgEntropy = totalEntropy / float64(entropySamples)
	}

	var suspiciousExts []string
	for ext := range extSet {
		if knownRansomwareExts[ext] {
			suspiciousExts = append(suspiciousExts, ext)
		}
	}

	// Trigger alert if average entropy is high or known ransomware extensions are proliferating
	isRansomware := (avgEntropy >= r.entropyLimit && count >= r.mutationCount) ||
		(len(suspiciousExts) > 0 && count >= 5)

	return RansomwareAlert{
		PID:            pid,
		FileCount:      count,
		AverageEntropy: avgEntropy,
		SuspiciousExts: suspiciousExts,
		IsRansomware:   isRansomware,
	}
}
