package plugin

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	RuntimeStateArmed   = "armed"
	RuntimeStateStopped = "stopped"
	RuntimeStateFailed  = "failed"
)

// RuntimeStatus is the public, non-secret health view for one plugin runtime.
// It deliberately excludes local bundle paths and the broker itself.
type RuntimeStatus struct {
	PluginID  string    `json:"plugin_id"`
	State     string    `json:"state"`
	Message   string    `json:"message,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	StoppedAt time.Time `json:"stopped_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type runtimeInstance struct {
	status RuntimeStatus
	broker *Broker
}

// RuntimeManager binds verified plugins to capability-scoped brokers and tracks
// runtime health. The current implementation is an execution-safe skeleton: it
// arms host-API access for a verified plugin but does not spawn processes, load
// wasm, or invoke artifact code.
type RuntimeManager struct {
	mu        sync.Mutex
	services  HostServices
	instances map[string]runtimeInstance
}

func NewRuntimeManager(services HostServices) *RuntimeManager {
	return &RuntimeManager{
		services:  services,
		instances: map[string]runtimeInstance{},
	}
}

// Start validates the loaded plugin, creates its broker, and marks it armed.
// The context is accepted now so future runners can honor cancellation without
// changing the call site.
func (m *RuntimeManager) Start(ctx context.Context, loaded Loaded) (RuntimeStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return RuntimeStatus{}, err
	}
	broker, err := NewBroker(loaded, m.services)
	if err != nil {
		return RuntimeStatus{}, err
	}
	now := time.Now().UTC()
	status := RuntimeStatus{
		PluginID:  loaded.Manifest.ID,
		State:     RuntimeStateArmed,
		Message:   "runtime broker armed; artifact execution is not enabled in this build",
		StartedAt: now,
		UpdatedAt: now,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.instances[loaded.Manifest.ID] = runtimeInstance{status: status, broker: broker}
	return status, nil
}

func (m *RuntimeManager) Stop(pluginID, message string) (RuntimeStatus, error) {
	if pluginID == "" {
		return RuntimeStatus{}, errors.New("plugin id is required")
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.instances[pluginID]
	if !ok {
		inst.status = RuntimeStatus{PluginID: pluginID, StartedAt: now}
	}
	inst.status.PluginID = pluginID
	inst.status.State = RuntimeStateStopped
	inst.status.Message = message
	inst.status.StoppedAt = now
	inst.status.UpdatedAt = now
	inst.broker = nil
	m.instances[pluginID] = inst
	return inst.status, nil
}

func (m *RuntimeManager) Status(pluginID string) (RuntimeStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.instances[pluginID]
	return inst.status, ok
}

func (m *RuntimeManager) Snapshot() map[string]RuntimeStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]RuntimeStatus, len(m.instances))
	for id, inst := range m.instances {
		out[id] = inst.status
	}
	return out
}

func (m *RuntimeManager) IsArmed(pluginID string) bool {
	status, ok := m.Status(pluginID)
	return ok && status.State == RuntimeStateArmed
}
