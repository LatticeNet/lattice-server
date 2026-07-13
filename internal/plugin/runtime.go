package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Runner    string    `json:"runner,omitempty"`
	Message   string    `json:"message,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	StoppedAt time.Time `json:"stopped_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RunnerStartRequest struct {
	PluginID string
	Loaded   Loaded
	Broker   *Broker
}

type RunnerStartResult struct {
	Message string
}

type RunnerStopRequest struct {
	PluginID string
	Reason   string
}

// Runner is the narrow runtime contract concrete plugin runtimes must satisfy.
// It receives a verified plugin and a capability-scoped broker, never raw server
// handles. Implementations must honor ctx cancellation and deadlines.
type Runner interface {
	Name() string
	Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error)
	Stop(ctx context.Context, req RunnerStopRequest) error
}

// InvokeRequest asks an armed plugin to perform one action. Payload is the raw
// JSON body handed to the plugin; the runner frames {action,payload} as a single
// stdin line and reads the reply from stdout.
type InvokeRequest struct {
	PluginID    string
	Action      string
	Payload     json.RawMessage
	Constraints InvokeConstraints
}

// InvokeConstraints are host-owned, invocation-scoped grants. They are never
// serialized to the child process and therefore cannot be expanded by plugin
// code after the operator call has been authorized.
type InvokeConstraints struct {
	OperatorTargets []string
}

// InvokeResponse is the decoded plugin reply. Result carries the plugin's body
// (e.g. a rendered plan) for the host to act on under its own privileges.
type InvokeResponse struct {
	OK      bool
	Message string
	Result  json.RawMessage
}

// Invoker is an optional runner capability: a request/response action protocol
// with the plugin. The system runner implements it; the noop runner does not.
type Invoker interface {
	Invoke(ctx context.Context, req InvokeRequest) (InvokeResponse, error)
}

type runtimeInstance struct {
	status     RuntimeStatus
	broker     *Broker
	runner     Runner
	generation uint64
}

type RuntimeManagerOptions struct {
	Services     HostServices
	Runners      map[string]Runner
	StartTimeout time.Duration
}

// RuntimeManager binds verified plugins to capability-scoped brokers and tracks
// runtime health. The current implementation is an execution-safe skeleton: it
// arms host-API access for a verified plugin but does not spawn processes, load
// wasm, or invoke artifact code.
type RuntimeManager struct {
	mu        sync.Mutex
	services  HostServices
	runners   map[string]Runner
	fallback  Runner
	timeout   time.Duration
	nextGen   uint64
	instances map[string]runtimeInstance
}

func NewRuntimeManager(services HostServices) *RuntimeManager {
	return NewRuntimeManagerWithOptions(RuntimeManagerOptions{Services: services})
}

func NewRuntimeManagerWithOptions(opts RuntimeManagerOptions) *RuntimeManager {
	timeout := opts.StartTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	runners := map[string]Runner{}
	for typ, runner := range opts.Runners {
		if runner != nil {
			runners[typ] = runner
		}
	}
	return &RuntimeManager{
		services:  opts.Services,
		runners:   runners,
		fallback:  noopRunner{},
		timeout:   timeout,
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
	runner := m.runnerFor(loaded.Manifest.Type)
	startCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	result, err := runner.Start(startCtx, RunnerStartRequest{
		PluginID: loaded.Manifest.ID,
		Loaded:   loaded,
		Broker:   broker,
	})
	now := time.Now().UTC()
	status := RuntimeStatus{
		PluginID:  loaded.Manifest.ID,
		Runner:    runner.Name(),
		StartedAt: now,
		UpdatedAt: now,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextGen++
	generation := m.nextGen
	if err != nil {
		status.State = RuntimeStateFailed
		status.Message = err.Error()
		m.instances[loaded.Manifest.ID] = runtimeInstance{status: status, generation: generation}
		return status, err
	}
	status.State = RuntimeStateArmed
	status.Message = result.Message
	if status.Message == "" {
		status.Message = fmt.Sprintf("%s runner armed", runner.Name())
	}
	m.instances[loaded.Manifest.ID] = runtimeInstance{status: status, broker: broker, runner: runner, generation: generation}
	return status, nil
}

func (m *RuntimeManager) Stop(pluginID, message string) (RuntimeStatus, error) {
	if pluginID == "" {
		return RuntimeStatus{}, errors.New("plugin id is required")
	}
	now := time.Now().UTC()
	m.mu.Lock()
	inst, ok := m.instances[pluginID]
	runner := inst.runner
	generation := inst.generation
	m.mu.Unlock()

	if ok && runner != nil {
		ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
		err := runner.Stop(ctx, RunnerStopRequest{PluginID: pluginID, Reason: message})
		cancel()
		if err != nil {
			m.mu.Lock()
			defer m.mu.Unlock()
			inst, ok = m.instances[pluginID]
			if ok && generation != 0 && inst.generation != generation {
				return inst.status, nil
			}
			if !ok {
				m.nextGen++
				inst = runtimeInstance{generation: m.nextGen, status: RuntimeStatus{PluginID: pluginID, StartedAt: now}}
			}
			inst.status.PluginID = pluginID
			inst.status.State = RuntimeStateFailed
			inst.status.Message = err.Error()
			inst.status.UpdatedAt = now
			// A plugin being disabled is no longer trusted with host access,
			// regardless of whether its Stop hook succeeded. Detach the broker and
			// runner here just as the success path does, so a failed Stop cannot
			// leave host-API access armed for a plugin we have decided to stop.
			inst.broker = nil
			inst.runner = nil
			m.instances[pluginID] = inst
			return inst.status, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok = m.instances[pluginID]
	if ok && generation != 0 && inst.generation != generation {
		return inst.status, nil
	}
	if !ok {
		m.nextGen++
		inst = runtimeInstance{generation: m.nextGen, status: RuntimeStatus{PluginID: pluginID, StartedAt: now}}
	}
	inst.status.PluginID = pluginID
	inst.status.State = RuntimeStateStopped
	inst.status.Message = message
	inst.status.StoppedAt = now
	inst.status.UpdatedAt = now
	inst.broker = nil
	inst.runner = nil
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

// Invoke dispatches one action to an armed plugin whose runner supports the
// request/response protocol. It fails closed if the plugin is not armed or its
// runner is not an Invoker (e.g. the noop runner), so a disabled or
// execution-disabled plugin can never be invoked.
func (m *RuntimeManager) Invoke(ctx context.Context, pluginID, action string, payload json.RawMessage) (InvokeResponse, error) {
	return m.InvokeConstrained(ctx, pluginID, action, payload, InvokeConstraints{})
}

func (m *RuntimeManager) InvokeConstrained(ctx context.Context, pluginID, action string, payload json.RawMessage, constraints InvokeConstraints) (InvokeResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	inst, ok := m.instances[pluginID]
	m.mu.Unlock()
	if !ok {
		return InvokeResponse{}, fmt.Errorf("plugin %q has no runtime", pluginID)
	}
	if inst.status.State != RuntimeStateArmed || inst.runner == nil {
		return InvokeResponse{}, fmt.Errorf("plugin %q is not armed", pluginID)
	}
	inv, ok := inst.runner.(Invoker)
	if !ok {
		return InvokeResponse{}, fmt.Errorf("plugin %q runner %q does not support invocation", pluginID, inst.runner.Name())
	}
	return inv.Invoke(ctx, InvokeRequest{PluginID: pluginID, Action: action, Payload: payload, Constraints: constraints})
}

func (m *RuntimeManager) runnerFor(pluginType string) Runner {
	if runner, ok := m.runners[pluginType]; ok && runner != nil {
		return runner
	}
	return m.fallback
}

type noopRunner struct{}

func (noopRunner) Name() string {
	return "noop"
}

func (noopRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	if err := ctx.Err(); err != nil {
		return RunnerStartResult{}, err
	}
	return RunnerStartResult{Message: "runtime broker armed; artifact execution is not enabled in this build"}, nil
}

func (noopRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	return ctx.Err()
}
