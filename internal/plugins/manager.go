package plugins

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/plugins/sandbox"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// PluginType classifies plugin execution responsibilities.
type PluginType string

const (
	PluginTypeInput        PluginType = "input"
	PluginTypeOutput       PluginType = "output"
	PluginTypeEnrichment   PluginType = "enrichment"
	PluginTypeAction       PluginType = "action"
	PluginTypeIntelligence PluginType = "intelligence"
)

// Info describes metadata and runtime status of a plugin.
type Info struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Type        PluginType     `json:"type"`
	Enabled     bool           `json:"enabled"`
	Status      string         `json:"status"`
	Permissions []string       `json:"permissions"`
	Config      map[string]any `json:"config"`
}

// Instance defines an executable plugin instance.
type Instance interface {
	Info() Info
	Init(ctx context.Context, cfg map[string]any) error
	OnEvent(ctx context.Context, evt event.Event) (event.Event, error)
	Close() error
}

// Manager coordinates plugin discovery, registration, sandbox execution, and event pipelines.
type Manager struct {
	mu          sync.RWMutex
	executionMu sync.Mutex
	plugins     map[string]Instance
	sandboxes   map[string]*sandbox.Sandbox
}

// NewManager initializes a new Plugin Manager.
func NewManager() *Manager {
	return &Manager{
		plugins:   make(map[string]Instance),
		sandboxes: make(map[string]*sandbox.Sandbox),
	}
}

// RegisterPlugin registers an active plugin instance with sandbox boundaries.
func (m *Manager) RegisterPlugin(instance Instance, sbConfig sandbox.Config) error {
	if sbConfig.MaxMemoryMB > 0 || len(sbConfig.Permissions) > 0 {
		return fmt.Errorf("plugin registration failed: in-process plugins cannot enforce memory or capability limits")
	}
	m.executionMu.Lock()
	defer m.executionMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()

	info := instance.Info()
	if info.ID == "" {
		return fmt.Errorf("plugin registration failed: missing ID")
	}

	if _, exists := m.plugins[info.ID]; exists {
		return fmt.Errorf("plugin '%s' already registered", info.ID)
	}

	sb := sandbox.New(sbConfig)
	m.plugins[info.ID] = instance
	m.sandboxes[info.ID] = sb

	slog.Info("registered plugin successfully", "id", info.ID, "name", info.Name, "type", info.Type)
	return nil
}

// UnregisterPlugin unloads a plugin.
func (m *Manager) UnregisterPlugin(id string) error {
	m.executionMu.Lock()
	defer m.executionMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()

	inst, exists := m.plugins[id]
	if !exists {
		return fmt.Errorf("plugin '%s' not found", id)
	}

	_ = inst.Close()
	delete(m.plugins, id)
	delete(m.sandboxes, id)

	slog.Info("unregistered plugin", "id", id)
	return nil
}

// ListPlugins returns information for all currently loaded plugins.
func (m *Manager) ListPlugins() []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]Info, 0, len(m.plugins))
	for _, inst := range m.plugins {
		list = append(list, inst.Info())
	}
	return list
}

// ProcessEvent forwards an event through all enabled enrichment plugins sequentially inside sandboxes.
func (m *Manager) ProcessEvent(ctx context.Context, evt event.Event) (event.Event, error) {
	m.executionMu.Lock()
	defer m.executionMu.Unlock()
	m.mu.RLock()
	type activePlugin struct {
		id   string
		inst Instance
		info Info
		sb   *sandbox.Sandbox
	}
	active := make([]activePlugin, 0, len(m.plugins))
	for id, inst := range m.plugins {
		info := inst.Info()
		if info.Enabled && info.Type == PluginTypeEnrichment {
			active = append(active, activePlugin{id: id, inst: inst, info: info, sb: m.sandboxes[id]})
		}
	}
	m.mu.RUnlock()
	sort.Slice(active, func(i, j int) bool { return active[i].id < active[j].id })

	currentEvt := evt

	for _, plugin := range active {
		sb := plugin.sb
		if sb == nil {
			sb = sandbox.New(sandbox.Config{Timeout: 5 * time.Second})
		}

		var enrichedEvt event.Event
		err := sb.Execute(ctx, plugin.info.Name, func(sCtx context.Context) error {
			res, err := plugin.inst.OnEvent(sCtx, currentEvt)
			if err != nil {
				return err
			}
			enrichedEvt = res
			return nil
		})

		if err != nil {
			slog.Warn("enrichment plugin failed, continuing pipeline", "plugin", plugin.info.Name, "error", err)
		} else {
			currentEvt = enrichedEvt
		}
	}

	return currentEvt, nil
}
