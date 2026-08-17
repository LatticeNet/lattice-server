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
	PluginID   string
	Generation uint64
	Loaded     Loaded
	Broker     *Broker
}

type RunnerStartResult struct {
	Message string
}

type RunnerStopRequest struct {
	PluginID   string
	Reason     string
	Generation uint64
}

// Runner is the narrow runtime contract concrete plugin runtimes must satisfy.
// It receives a verified plugin and a capability-scoped broker, never raw server
// handles. Implementations must honor ctx cancellation and deadlines.
type Runner interface {
	Name() string
	Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error)
	Stop(ctx context.Context, req RunnerStopRequest) error
}

// TransactionalRunner separates candidate preparation from admission. A
// prepared generation must not be invokable until ActivateGeneration succeeds;
// failed/stale candidates are removed with AbortGeneration, while an old
// committed generation is retired only after the manager publishes its
// replacement.
type TransactionalRunner interface {
	Runner
	Prepare(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error)
	ActivateGeneration(pluginID string, generation uint64) error
	AbortGeneration(ctx context.Context, pluginID string, generation uint64) error
	RetireGeneration(ctx context.Context, pluginID string, generation uint64) error
}

type RunnerCloser interface {
	StopAll(ctx context.Context) error
}

// InvokeRequest asks an armed plugin to perform one action. Payload is the raw
// JSON body handed to the plugin; the runner frames {action,payload} as a single
// stdin line and reads the reply from stdout.
type InvokeRequest struct {
	PluginID    string
	Generation  uint64
	Action      string
	Payload     json.RawMessage
	Constraints InvokeConstraints
}

// InvokeConstraints are host-owned, invocation-scoped grants. They are never
// serialized to the child process and therefore cannot be expanded by plugin
// code after the operator call has been authorized.
type InvokeConstraints struct {
	OperatorTargets []string
	// Budget is the signed method-level runtime budget resolved by the host. Nil
	// is the additive compatibility path for already-signed manifests and resolves
	// to the old global defaults with a host warning.
	Budget *InvokeBudgetSpec
	// BudgetLabel is a stable service/method label used only for host logs.
	BudgetLabel string
	// Operation is the one-time authority for an approved host-risk operation (§9.3).
	// Like OperatorTargets it stays on the host side of the boundary: the plugin never
	// receives it, so it cannot forge or widen one — it can only make a host call that
	// the broker then checks against it.
	Operation *OperationGrant
}

// InvokeResponse is the decoded plugin reply. Result carries the plugin's body
// (e.g. a rendered plan) for the host to act on under its own privileges.
type InvokeResponse struct {
	OK       bool            `json:"ok"`
	Message  string          `json:"message,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	Warnings []string        `json:"warnings,omitempty"`
}

// Invoker is an optional runner capability: a request/response action protocol
// with the plugin. The system runner implements it; the noop runner does not.
type Invoker interface {
	Invoke(ctx context.Context, req InvokeRequest) (InvokeResponse, error)
}

type InvocationGenerationLease interface {
	Invoke(ctx context.Context, req InvokeRequest) (InvokeResponse, error)
	Release()
}

type GenerationLeasingRunner interface {
	AcquireInvocation(pluginID string, generation uint64) (InvocationGenerationLease, error)
}

type runtimeInstance struct {
	status     RuntimeStatus
	broker     *Broker
	runner     Runner
	generation uint64
}

type pendingRuntimeStart struct {
	generation uint64
	cancel     context.CancelFunc
	done       chan struct{}
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
	mu            sync.Mutex
	services      HostServices
	runners       map[string]Runner
	fallback      Runner
	timeout       time.Duration
	nextGen       uint64
	latestGen     map[string]uint64
	pendingStarts map[string]map[uint64]pendingRuntimeStart
	instances     map[string]runtimeInstance
	closing       bool
	closeDone     chan struct{}
	closeErr      error
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
		services:      opts.Services,
		runners:       runners,
		fallback:      noopRunner{},
		timeout:       timeout,
		latestGen:     map[string]uint64{},
		pendingStarts: map[string]map[uint64]pendingRuntimeStart{},
		instances:     map[string]runtimeInstance{},
		closeDone:     make(chan struct{}),
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
	broker.attachAuthority(newGenerationAuthority())
	runner := m.runnerFor(loaded.Manifest.Type)
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		broker.authority.revoke()
		return RuntimeStatus{}, errors.New("runtime manager is closed")
	}
	if current, ok := m.instances[loaded.Manifest.ID]; ok && current.status.State == RuntimeStateArmed {
		_, newTransactional := runner.(TransactionalRunner)
		_, oldTransactional := current.runner.(TransactionalRunner)
		if !newTransactional || !oldTransactional {
			m.mu.Unlock()
			broker.authority.revoke()
			return current.status, errors.New("runtime replacement requires a transactional runner")
		}
	}
	m.nextGen++
	generation := m.nextGen
	m.latestGen[loaded.Manifest.ID] = generation
	startCtx, cancel := context.WithTimeout(ctx, m.timeout)
	if m.pendingStarts[loaded.Manifest.ID] == nil {
		m.pendingStarts[loaded.Manifest.ID] = map[uint64]pendingRuntimeStart{}
	}
	startDone := make(chan struct{})
	m.pendingStarts[loaded.Manifest.ID][generation] = pendingRuntimeStart{generation: generation, cancel: cancel, done: startDone}
	m.mu.Unlock()
	defer func() {
		cancel()
		m.mu.Lock()
		if pending := m.pendingStarts[loaded.Manifest.ID]; pending != nil {
			delete(pending, generation)
			if len(pending) == 0 {
				delete(m.pendingStarts, loaded.Manifest.ID)
			}
		}
		m.mu.Unlock()
		close(startDone)
	}()
	req := RunnerStartRequest{
		PluginID:   loaded.Manifest.ID,
		Generation: generation,
		Loaded:     loaded,
		Broker:     broker,
	}
	transactional, isTransactional := runner.(TransactionalRunner)
	var result RunnerStartResult
	if isTransactional {
		result, err = transactional.Prepare(startCtx, req)
	} else {
		result, err = runner.Start(startCtx, req)
	}
	now := time.Now().UTC()
	status := RuntimeStatus{
		PluginID:  loaded.Manifest.ID,
		Runner:    runner.Name(),
		StartedAt: now,
		UpdatedAt: now,
	}
	m.mu.Lock()
	current, currentOK := m.instances[loaded.Manifest.ID]
	if m.closing || m.latestGen[loaded.Manifest.ID] != generation {
		m.mu.Unlock()
		broker.authority.revoke()
		if err == nil {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), m.timeout)
			if isTransactional {
				_ = transactional.AbortGeneration(stopCtx, loaded.Manifest.ID, generation)
			} else {
				_ = runner.Stop(stopCtx, RunnerStopRequest{PluginID: loaded.Manifest.ID, Reason: "stale concurrent start", Generation: generation})
			}
			stopCancel()
		}
		if currentOK {
			return current.status, fmt.Errorf("stale runtime generation %d", generation)
		}
		return RuntimeStatus{}, fmt.Errorf("stale runtime generation %d", generation)
	}
	if err != nil {
		broker.authority.revoke()
		if currentOK && current.status.State == RuntimeStateArmed {
			m.mu.Unlock()
			return current.status, err
		}
		status.State = RuntimeStateFailed
		status.Message = err.Error()
		m.instances[loaded.Manifest.ID] = runtimeInstance{status: status, generation: generation}
		m.mu.Unlock()
		return status, err
	}
	status.State = RuntimeStateArmed
	status.Message = result.Message
	if status.Message == "" {
		status.Message = fmt.Sprintf("%s runner armed", runner.Name())
	}
	if isTransactional {
		if activateErr := transactional.ActivateGeneration(loaded.Manifest.ID, generation); activateErr != nil {
			if !currentOK || current.status.State != RuntimeStateArmed {
				status.State = RuntimeStateFailed
				status.Message = activateErr.Error()
				m.instances[loaded.Manifest.ID] = runtimeInstance{status: status, generation: generation}
			}
			m.mu.Unlock()
			broker.authority.revoke()
			abortCtx, abortCancel := context.WithTimeout(context.Background(), m.timeout)
			_ = transactional.AbortGeneration(abortCtx, loaded.Manifest.ID, generation)
			abortCancel()
			if currentOK && current.status.State == RuntimeStateArmed {
				return current.status, activateErr
			}
			return status, activateErr
		}
	}
	old := current
	m.instances[loaded.Manifest.ID] = runtimeInstance{status: status, broker: broker, runner: runner, generation: generation}
	m.mu.Unlock()
	if currentOK && old.runner != nil && old.generation != generation {
		if oldTransactional, ok := old.runner.(TransactionalRunner); ok {
			retireCtx, retireCancel := context.WithTimeout(context.Background(), m.timeout)
			retireErr := oldTransactional.RetireGeneration(retireCtx, loaded.Manifest.ID, old.generation)
			retireCancel()
			if retireErr != nil {
				m.mu.Lock()
				current := m.instances[loaded.Manifest.ID]
				if current.generation == generation {
					current.status.Message = fmt.Sprintf("%s; prior generation retirement degraded: %v", current.status.Message, retireErr)
					current.status.UpdatedAt = time.Now().UTC()
					m.instances[loaded.Manifest.ID] = current
					status = current.status
				}
				m.mu.Unlock()
				return status, fmt.Errorf("runtime generation %d armed but prior generation %d retirement failed: %w", generation, old.generation, retireErr)
			}
		}
	}
	return status, nil
}

func (m *RuntimeManager) Stop(pluginID, message string) (RuntimeStatus, error) {
	if pluginID == "" {
		return RuntimeStatus{}, errors.New("plugin id is required")
	}
	m.mu.Lock()
	m.nextGen++
	tombstone := m.nextGen
	m.latestGen[pluginID] = tombstone
	for _, pending := range m.pendingStarts[pluginID] {
		if pending.cancel != nil {
			pending.cancel()
		}
	}
	now := time.Now().UTC()
	inst, ok := m.instances[pluginID]
	runner := inst.runner
	oldBroker := inst.broker
	generation := inst.generation
	if !ok {
		inst = runtimeInstance{generation: tombstone, status: RuntimeStatus{PluginID: pluginID, StartedAt: now}}
	}
	inst.status.PluginID = pluginID
	inst.status.State = RuntimeStateStopped
	inst.status.Message = message
	inst.status.StoppedAt = now
	inst.status.UpdatedAt = now
	inst.broker = nil
	inst.runner = nil
	m.instances[pluginID] = inst
	if ok && oldBroker != nil && oldBroker.authority != nil {
		oldBroker.authority.revoke()
	}
	stopped := inst.status
	m.mu.Unlock()

	if ok && runner != nil {
		ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
		stopGeneration := generation
		if _, transactional := runner.(TransactionalRunner); transactional {
			stopGeneration = tombstone
		}
		runnerDone := make(chan error, 1)
		authorityDone := make(chan error, 1)
		go func() {
			runnerDone <- runner.Stop(ctx, RunnerStopRequest{PluginID: pluginID, Reason: message, Generation: stopGeneration})
		}()
		go func() {
			if oldBroker != nil && oldBroker.authority != nil {
				authorityDone <- oldBroker.authority.wait(ctx)
				return
			}
			authorityDone <- nil
		}()
		var runnerErr, authorityErr error
		remaining := 2
		for remaining > 0 {
			select {
			case runnerErr = <-runnerDone:
				runnerDone = nil
				remaining--
			case authorityErr = <-authorityDone:
				authorityDone = nil
				remaining--
			case <-ctx.Done():
				runnerErr = errors.Join(runnerErr, ctx.Err())
				remaining = 0
			}
		}
		err := errors.Join(runnerErr, authorityErr)
		cancel()
		if err != nil {
			m.mu.Lock()
			defer m.mu.Unlock()
			current := m.instances[pluginID]
			if current.generation != generation && current.generation != tombstone {
				return current.status, nil
			}
			current.status.State = RuntimeStateFailed
			current.status.Message = err.Error()
			current.status.UpdatedAt = now
			m.instances[pluginID] = current
			return current.status, err
		}
	}
	return stopped, nil
}

// Close atomically closes runtime admission, invalidates every pending start,
// and joins runner-owned generations before returning.
func (m *RuntimeManager) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.closing {
		done := m.closeDone
		m.mu.Unlock()
		select {
		case <-done:
			m.mu.Lock()
			err := m.closeErr
			m.mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.closing = true
	var pendingDone []<-chan struct{}
	for pluginID, attempts := range m.pendingStarts {
		m.nextGen++
		m.latestGen[pluginID] = m.nextGen
		for _, pending := range attempts {
			if pending.cancel != nil {
				pending.cancel()
			}
			if pending.done != nil {
				pendingDone = append(pendingDone, pending.done)
			}
		}
	}
	runners := make(map[Runner]struct{})
	for _, runner := range m.runners {
		if runner != nil {
			runners[runner] = struct{}{}
		}
	}
	for pluginID, inst := range m.instances {
		if inst.runner != nil {
			runners[inst.runner] = struct{}{}
		}
		if inst.broker != nil && inst.broker.authority != nil {
			inst.broker.authority.revoke()
		}
		inst.runner = nil
		inst.broker = nil
		inst.status.State = RuntimeStateStopped
		inst.status.Message = "runtime manager closed"
		inst.status.StoppedAt = time.Now().UTC()
		inst.status.UpdatedAt = inst.status.StoppedAt
		m.instances[pluginID] = inst
	}
	m.mu.Unlock()
	go m.finishClose(runners, pendingDone)
	select {
	case <-m.closeDone:
		m.mu.Lock()
		err := m.closeErr
		m.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *RuntimeManager) finishClose(runners map[Runner]struct{}, pendingDone []<-chan struct{}) {
	var joined error
	for runner := range runners {
		if closer, ok := runner.(RunnerCloser); ok {
			joined = errors.Join(joined, closer.StopAll(context.Background()))
		}
	}
	for _, done := range pendingDone {
		<-done
	}
	m.mu.Lock()
	m.closeErr = joined
	close(m.closeDone)
	m.mu.Unlock()
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
	if m.closing {
		m.mu.Unlock()
		return InvokeResponse{}, errors.New("runtime manager is closed")
	}
	inst, ok := m.instances[pluginID]
	if !ok {
		m.mu.Unlock()
		return InvokeResponse{}, fmt.Errorf("plugin %q has no runtime", pluginID)
	}
	if inst.status.State != RuntimeStateArmed || inst.runner == nil {
		m.mu.Unlock()
		return InvokeResponse{}, fmt.Errorf("plugin %q is not armed", pluginID)
	}
	inv, ok := inst.runner.(Invoker)
	if !ok {
		m.mu.Unlock()
		return InvokeResponse{}, fmt.Errorf("plugin %q runner %q does not support invocation", pluginID, inst.runner.Name())
	}
	req := InvokeRequest{PluginID: pluginID, Generation: inst.generation, Action: action, Payload: payload, Constraints: constraints}
	if leasing, ok := inst.runner.(GenerationLeasingRunner); ok {
		lease, err := leasing.AcquireInvocation(pluginID, inst.generation)
		m.mu.Unlock()
		if err != nil {
			return InvokeResponse{}, err
		}
		defer lease.Release()
		return lease.Invoke(ctx, req)
	}
	m.mu.Unlock()
	return inv.Invoke(ctx, req)
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
