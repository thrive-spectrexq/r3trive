package anomaly

import (
	"sync"
	"time"
)

// EntityProfile tracks normal behavior baselines for a host or user entity.
type EntityProfile struct {
	EntityID         string
	ObservedProcesses map[string]int
	OutboundDestIPs  map[string]int
	TotalEvents      int64
	FirstSeen        time.Time
	LastSeen         time.Time
}

// BaselineManager coordinates UEBA baseline learning and anomaly thresholding.
type BaselineManager struct {
	profiles        map[string]*EntityProfile
	forest          *IsolationForest
	learningPeriod  time.Duration
	startTime       time.Time
	mu              sync.RWMutex
}

// NewBaselineManager creates a UEBA baseline manager with a defined learning duration.
func NewBaselineManager(learningPeriod time.Duration) *BaselineManager {
	if learningPeriod <= 0 {
		learningPeriod = 24 * time.Hour
	}
	return &BaselineManager{
		profiles:       make(map[string]*EntityProfile),
		forest:         NewIsolationForest(50, 64),
		learningPeriod: learningPeriod,
		startTime:      time.Now(),
	}
}

// IsLearning returns true if the engine is still establishing baseline activity.
func (b *BaselineManager) IsLearning() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return time.Since(b.startTime) < b.learningPeriod
}

// RecordProcessEvent updates the baseline profile for an entity and evaluates novelty.
func (b *BaselineManager) RecordProcessEvent(entityID string, processName string) (isNewProcess bool, anomalyScore float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	profile, exists := b.profiles[entityID]
	if !exists {
		profile = &EntityProfile{
			EntityID:          entityID,
			ObservedProcesses: make(map[string]int),
			OutboundDestIPs:   make(map[string]int),
			FirstSeen:         time.Now(),
		}
		b.profiles[entityID] = profile
	}

	profile.TotalEvents++
	profile.LastSeen = time.Now()

	count := profile.ObservedProcesses[processName]
	profile.ObservedProcesses[processName]++

	isNew := count == 0
	featureVector := Point{
		float64(len(profile.ObservedProcesses)),
		float64(profile.TotalEvents),
		float64(count),
	}

	score := b.forest.AnomalyScore(featureVector)
	return isNew, score
}
