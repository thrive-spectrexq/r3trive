package anomaly

import (
	"math"
	"sync"
	"time"
)

// BeaconTracker records inter-arrival timestamps for a specific destination endpoint.
type BeaconTracker struct {
	timestamps []time.Time
	maxSamples int
	mu         sync.Mutex
}

// NewBeaconTracker creates a tracker with a maximum window of sample timestamps.
func NewBeaconTracker(maxSamples int) *BeaconTracker {
	if maxSamples < 5 {
		maxSamples = 20
	}
	return &BeaconTracker{
		timestamps: make([]time.Time, 0, maxSamples),
		maxSamples: maxSamples,
	}
}

// Record observes an event occurrence timestamp.
func (t *BeaconTracker) Record(ts time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.timestamps) >= t.maxSamples {
		t.timestamps = t.timestamps[1:]
	}
	t.timestamps = append(t.timestamps, ts)
}

// BeaconMetrics holds the statistical analysis of connection intervals.
type BeaconMetrics struct {
	Count    int           `json:"count"`
	Mean     time.Duration `json:"mean_interval"`
	StdDev   time.Duration `json:"std_dev"`
	CV       float64       `json:"coefficient_of_variation"`
	IsBeacon bool          `json:"is_beacon"`
}

// Analyze calculates the Coefficient of Variation (CV = StdDev / Mean).
// A CV threshold below 0.15 indicates highly periodic, automated traffic (C2 beaconing).
func (t *BeaconTracker) Analyze(cvThreshold float64) BeaconMetrics {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := len(t.timestamps)
	if n < 5 {
		return BeaconMetrics{Count: n}
	}

	intervals := make([]float64, n-1)
	var sum float64
	for i := 1; i < n; i++ {
		diff := t.timestamps[i].Sub(t.timestamps[i-1]).Seconds()
		if diff < 0 {
			diff = -diff
		}
		intervals[i-1] = diff
		sum += diff
	}

	mean := sum / float64(len(intervals))
	if mean <= 0 {
		return BeaconMetrics{Count: n}
	}

	var varianceSum float64
	for _, interval := range intervals {
		diff := interval - mean
		varianceSum += diff * diff
	}

	variance := varianceSum / float64(len(intervals))
	stdDev := math.Sqrt(variance)
	cv := stdDev / mean

	isBeacon := cv <= cvThreshold && mean >= 0.5 // minimum 500ms interval

	return BeaconMetrics{
		Count:    n,
		Mean:     time.Duration(mean * float64(time.Second)),
		StdDev:   time.Duration(stdDev * float64(time.Second)),
		CV:       cv,
		IsBeacon: isBeacon,
	}
}
