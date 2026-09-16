package plugins

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/plugins/sandbox"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type dummyEnrichmentPlugin struct{}

func (d *dummyEnrichmentPlugin) Info() Info {
	return Info{
		ID:      "dummy-enricher",
		Name:    "Dummy Enricher",
		Type:    PluginTypeEnrichment,
		Enabled: true,
	}
}

func (d *dummyEnrichmentPlugin) Init(ctx context.Context, cfg map[string]any) error {
	return nil
}

func (d *dummyEnrichmentPlugin) OnEvent(ctx context.Context, evt event.Event) (event.Event, error) {
	evt.Sensor = evt.Sensor + "_enriched"
	return evt, nil
}

func (d *dummyEnrichmentPlugin) Close() error {
	return nil
}

func TestPluginManager(t *testing.T) {
	mgr := NewManager()
	plugin := &dummyEnrichmentPlugin{}

	err := mgr.RegisterPlugin(plugin, sandbox.Config{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("RegisterPlugin failed: %v", err)
	}

	plugins := mgr.ListPlugins()
	if len(plugins) != 1 || plugins[0].ID != "dummy-enricher" {
		t.Errorf("expected 1 plugin with ID dummy-enricher")
	}

	ctx := context.Background()
	evt := event.Event{
		ID:     "evt-100",
		Sensor: "base_sensor",
	}

	enriched, err := mgr.ProcessEvent(ctx, evt)
	if err != nil {
		t.Fatalf("ProcessEvent failed: %v", err)
	}
	if enriched.Sensor != "base_sensor_enriched" {
		t.Errorf("expected enriched sensor name, got %s", enriched.Sensor)
	}

	if err := mgr.UnregisterPlugin("dummy-enricher"); err != nil {
		t.Errorf("UnregisterPlugin failed: %v", err)
	}
}

func TestPluginManagerRejectsUnenforceableSandboxLimits(t *testing.T) {
	mgr := NewManager()
	err := mgr.RegisterPlugin(&dummyEnrichmentPlugin{}, sandbox.Config{Permissions: []sandbox.Permission{sandbox.PermissionNetwork}})
	if err == nil {
		t.Fatal("expected registration with unenforceable permissions to fail")
	}
}
