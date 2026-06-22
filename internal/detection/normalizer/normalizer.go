// Package normalizer maps platform-specific raw events to the common
// R3TRIVE event schema defined in pkg/event.
package normalizer

import (
	"log/slog"
	"runtime"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Normalizer transforms raw platform-specific event data into the
// canonical Event schema.
type Normalizer struct {
	platform string
}

// New creates a new Normalizer for the current platform.
func New() *Normalizer {
	return &Normalizer{
		platform: runtime.GOOS,
	}
}

// Normalize transforms a raw event into the canonical schema.
// For now, events from mock sensors are already normalized.
// This will be extended when native sensors produce raw platform-specific data.
func (n *Normalizer) Normalize(evt event.Event) event.Event {
	slog.Debug("normalizing event", "id", evt.ID, "type", evt.Type, "platform", n.platform)

	// Ensure required fields are populated
	if evt.Host.OS == "" {
		evt.Host.OS = n.platform
	}
	if evt.Host.Arch == "" {
		evt.Host.Arch = runtime.GOARCH
	}

	return evt
}
