package correlation

import (
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Window is a sliding temporal window that groups events within a time span.
// Used by the correlation engine to detect multi-event attack patterns.
type Window struct {
	mu       sync.RWMutex
	duration time.Duration
	events   []event.Event
}

// NewWindow creates a new temporal window with the given duration.
func NewWindow(d time.Duration) *Window {
	return &Window{
		duration: d,
		events:   make([]event.Event, 0, 100),
	}
}

// Add inserts an event into the window and prunes expired entries.
func (w *Window) Add(evt event.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.events = append(w.events, evt)
	w.prune()
}

// Events returns a snapshot of all events within the window.
func (w *Window) Events() []event.Event {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]event.Event, len(w.events))
	copy(result, w.events)
	return result
}

// Len returns the number of events in the window.
func (w *Window) Len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.events)
}

// prune removes events older than the window duration. Must hold write lock.
func (w *Window) prune() {
	cutoff := time.Now().Add(-w.duration)
	i := 0
	for i < len(w.events) && w.events[i].Timestamp.Before(cutoff) {
		i++
	}
	if i > 0 {
		w.events = w.events[i:]
	}
}
