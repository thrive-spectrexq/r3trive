package plugins

import (
	"context"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const (
	// CurrentAPIVersion is the semantic version of the Plugin SDK.
	CurrentAPIVersion = "1.0.0"
)

// PluginMetadata contains registration info and version guarantees.
type PluginMetadata struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	APIVersion  string     `json:"api_version"`
	Type        PluginType `json:"type"`
	Description string     `json:"description"`
}

// Plugin defines the lifecycle and execution interface for R3TRIVE plugins.
type Plugin interface {
	Metadata() PluginMetadata
	Init(ctx context.Context, config map[string]interface{}) error
	Close() error
}

// OutputPlugin exports events and alerts to external SIEM/data lakes.
type OutputPlugin interface {
	Plugin
	EmitEvent(ctx context.Context, evt event.Event) error
	EmitAlert(ctx context.Context, alert event.Alert) error
}

// ActionPlugin executes containment or ticketing actions.
type ActionPlugin interface {
	Plugin
	ExecuteAction(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error)
}

// IntelligencePlugin queries or ingests threat intelligence indicators.
type IntelligencePlugin interface {
	Plugin
	LookupIOC(ctx context.Context, iocType string, value string) (map[string]interface{}, error)
}
