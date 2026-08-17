package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	RuntimeStateArmed    = "armed"
	RuntimeStateStopping = "stopping"
	RuntimeStateStopped  = "stopped"
	RuntimeStateDegraded = "degraded"
	RuntimeStateFailed   = "failed"
)

// RuntimeShutdownError reports a caller-bounded observation of physical
// shutdown without transferring or abandoning manager ownership.
type RuntimeShutdownError struct {
	PluginID      string
	Stage         string
	PendingStages []string
	Err           error
}

func (e *RuntimeShutdownError) Error() string {
	if e.PluginID == "" {
		return fmt.Sprintf("runtime shutdown %s: %v", e.Stage, e.Err)
	}
	return fmt.Sprintf("runtime %s shutdown %s: %v", e.PluginID, e.Stage, e.Err)
}

func (e *RuntimeShutdownError) Unwrap() error { return e.Err }

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
	generation  uint64
	cancel      context.CancelFunc
	prepareDone chan struct{}
	runner      Runner
	broker      *Broker
	cleanup     *runtimePendingCleanup
}

type runtimePendingCleanup struct {
	mu   sync.Mutex
	once sync.Once
	done chan struct{}
	err  error
}

func newRuntimePendingCleanup() *runtimePendingCleanup {
	return &runtimePendingCleanup{done: make(chan struct{})}
}

func (c *runtimePendingCleanup) finish(err error) {
	if c == nil {
		return
	}
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.done)
	})
}

func (c *runtimePendingCleanup) result() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

type runtimeStopFuture struct {
	pluginID       string
	generation     uint64
	tombstone      uint64
	stopGeneration uint64
	message        string
	runner         Runner
	broker         *Broker
	pendingStarts  []pendingRuntimeStart
	predecessors   []*runtimeStopFuture
	pendingStages  map[string]int
	startOnce      sync.Once
	done           chan struct{}
	status         RuntimeStatus
	err            error
}

func (f *runtimeStopFuture) start(manager *RuntimeManager) {
	if f == nil {
		return
	}
	f.startOnce.Do(func() { go manager.finishRuntimeStop(f) })
}

type runtimeShutdownPart struct {
	stage     string
	pluginIDs []string
	err       error
}

type runtimePendingClose struct {
	pluginID string
	stage    string
	done     <-chan struct{}
	cleanup  *runtimePendingCleanup
}

const (
	runtimeStoppingMessage = "runtime shutdown in progress"
	runtimePendingMessage  = "runtime shutdown pending"
	runtimeStoppedMessage  = "runtime shutdown complete"
	runtimeDegradedMessage = "runtime shutdown incomplete"
)

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
	stopFutures   map[string]map[uint64]*runtimeStopFuture
	closing       bool
	closeDone     chan struct{}
	closeErr      error
	closePending  map[string]int
	closeEpochs   map[string]uint64
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
		stopFutures:   map[string]map[uint64]*runtimeStopFuture{},
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
	prepareDone := make(chan struct{})
	cleanup := newRuntimePendingCleanup()
	m.pendingStarts[loaded.Manifest.ID][generation] = pendingRuntimeStart{
		generation: generation, cancel: cancel, prepareDone: prepareDone, runner: runner, broker: broker, cleanup: cleanup,
	}
	m.mu.Unlock()
	cleanupOwned := false
	removePending := func() {
		m.mu.Lock()
		if pending := m.pendingStarts[loaded.Manifest.ID]; pending != nil {
			delete(pending, generation)
			if len(pending) == 0 {
				delete(m.pendingStarts, loaded.Manifest.ID)
			}
		}
		m.mu.Unlock()
	}
	launchCleanup := func(cleanupFn func() error) {
		cleanupOwned = true
		cancel()
		go func() {
			cleanupErr := cleanupFn()
			cleanup.finish(cleanupErr)
			if cleanupErr == nil {
				removePending()
			}
		}()
	}
	defer func() {
		close(prepareDone)
		if !cleanupOwned {
			cancel()
			cleanup.finish(nil)
			removePending()
		}
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
			launchCleanup(func() error {
				if isTransactional {
					return transactional.AbortGeneration(context.Background(), loaded.Manifest.ID, generation)
				}
				return runner.Stop(context.Background(), RunnerStopRequest{PluginID: loaded.Manifest.ID, Reason: "stale concurrent start", Generation: generation})
			})
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
			launchCleanup(func() error {
				return transactional.AbortGeneration(context.Background(), loaded.Manifest.ID, generation)
			})
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
					current.status.Message = boundedRuntimeStatusMessage(current.status.Message + "; prior generation retirement degraded")
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
	if m.closing {
		done := m.closeDone
		status := m.instances[pluginID].status
		m.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
		defer cancel()
		select {
		case <-done:
			m.mu.Lock()
			status = m.instances[pluginID].status
			err := m.closeErr
			m.mu.Unlock()
			return status, err
		case <-ctx.Done():
			return status, &RuntimeShutdownError{
				PluginID: pluginID, Stage: "shutdown-pending", PendingStages: []string{"manager-close"}, Err: ctx.Err(),
			}
		}
	}
	if current, ok := m.instances[pluginID]; ok && m.latestGen[pluginID] == current.generation {
		if future := m.stopFutures[pluginID][current.generation]; future != nil {
			m.mu.Unlock()
			return m.waitRuntimeStop(future)
		}
	}
	var predecessors []*runtimeStopFuture
	for epoch, future := range m.stopFutures[pluginID] {
		select {
		case <-future.done:
			if future.err == nil {
				delete(m.stopFutures[pluginID], epoch)
				continue
			}
		default:
		}
		predecessors = append(predecessors, future)
	}
	m.nextGen++
	tombstone := m.nextGen
	m.latestGen[pluginID] = tombstone
	var pendingStarts []pendingRuntimeStart
	for _, pending := range m.pendingStarts[pluginID] {
		if pending.cancel != nil {
			pending.cancel()
		}
		if pending.broker != nil && pending.broker.authority != nil {
			pending.broker.authority.revoke()
		}
		pendingStarts = append(pendingStarts, pending)
	}
	delete(m.pendingStarts, pluginID)
	now := time.Now().UTC()
	inst, ok := m.instances[pluginID]
	runner := inst.runner
	oldBroker := inst.broker
	generation := inst.generation
	if !ok {
		inst = runtimeInstance{generation: tombstone, status: RuntimeStatus{PluginID: pluginID, StartedAt: now}}
	}
	inst.status.PluginID = pluginID
	inst.status.State = RuntimeStateStopping
	inst.status.Message = runtimeStoppingMessage
	inst.status.StoppedAt = time.Time{}
	inst.status.UpdatedAt = now
	inst.generation = tombstone
	inst.broker = nil
	inst.runner = nil
	if ok && oldBroker != nil && oldBroker.authority != nil {
		oldBroker.authority.revoke()
	}
	stopGeneration := generation
	if _, transactional := runner.(TransactionalRunner); transactional {
		stopGeneration = tombstone
	}
	future := &runtimeStopFuture{
		pluginID: pluginID, generation: generation, tombstone: tombstone,
		stopGeneration: stopGeneration, message: message, runner: runner, broker: oldBroker,
		pendingStarts: append([]pendingRuntimeStart(nil), pendingStarts...),
		predecessors:  append([]*runtimeStopFuture(nil), predecessors...),
		pendingStages: map[string]int{}, done: make(chan struct{}), status: inst.status,
	}
	if runner != nil {
		future.pendingStages["runner-cleanup"]++
	}
	if oldBroker != nil && oldBroker.authority != nil {
		future.pendingStages["authority-drain"]++
	}
	for _, pending := range pendingStarts {
		if pending.prepareDone != nil {
			future.pendingStages["pending-starts"]++
		}
		if pending.cleanup != nil && pending.cleanup.done != nil {
			future.pendingStages["pending-cleanup"]++
		}
		if pending.broker != nil && pending.broker.authority != nil {
			future.pendingStages["authority-drain"]++
		}
	}
	if len(predecessors) != 0 {
		future.pendingStages["predecessor-stops"] = len(predecessors)
	}
	m.instances[pluginID] = inst
	if m.stopFutures[pluginID] == nil {
		m.stopFutures[pluginID] = map[uint64]*runtimeStopFuture{}
	}
	m.stopFutures[pluginID][tombstone] = future
	m.mu.Unlock()
	future.start(m)
	return m.waitRuntimeStop(future)
}

func (m *RuntimeManager) finishRuntimeStop(future *runtimeStopFuture) {
	results := make(chan runtimeShutdownPart, 2+3*len(future.pendingStarts)+len(future.predecessors))
	remaining := 0
	if future.runner != nil {
		remaining++
		go func() {
			results <- runtimeShutdownPart{stage: "runner-cleanup", err: future.runner.Stop(context.Background(), RunnerStopRequest{
				PluginID: future.pluginID, Reason: future.message, Generation: future.stopGeneration,
			})}
		}()
	}
	if future.broker != nil && future.broker.authority != nil {
		remaining++
		go func() {
			results <- runtimeShutdownPart{stage: "authority-drain", err: future.broker.authority.wait(context.Background())}
		}()
	}
	for _, pending := range future.pendingStarts {
		if pending.prepareDone != nil {
			remaining++
			go func(pending pendingRuntimeStart) {
				<-pending.prepareDone
				results <- runtimeShutdownPart{stage: "pending-starts"}
			}(pending)
		}
		if pending.cleanup != nil && pending.cleanup.done != nil {
			remaining++
			go func(cleanup *runtimePendingCleanup) {
				<-cleanup.done
				results <- runtimeShutdownPart{stage: "pending-cleanup", err: cleanup.result()}
			}(pending.cleanup)
		}
		if pending.broker != nil && pending.broker.authority != nil {
			remaining++
			go func(authority *generationAuthority) {
				results <- runtimeShutdownPart{stage: "authority-drain", err: authority.wait(context.Background())}
			}(pending.broker.authority)
		}
	}
	for _, predecessor := range future.predecessors {
		remaining++
		predecessor.start(m)
		go func(predecessor *runtimeStopFuture) {
			<-predecessor.done
			results <- runtimeShutdownPart{stage: "predecessor-stops", err: predecessor.err}
		}(predecessor)
	}
	var joined error
	for range remaining {
		result := <-results
		joined = errors.Join(joined, result.err)
		m.mu.Lock()
		future.pendingStages[result.stage]--
		if future.pendingStages[result.stage] == 0 {
			delete(future.pendingStages, result.stage)
		}
		m.mu.Unlock()
	}

	m.mu.Lock()
	future.err = joined
	now := time.Now().UTC()
	if joined != nil {
		future.status.State = RuntimeStateDegraded
		future.status.Message = runtimeDegradedMessage
		future.status.StoppedAt = time.Time{}
	} else {
		future.status.State = RuntimeStateStopped
		future.status.Message = runtimeStoppedMessage
		future.status.StoppedAt = now
	}
	future.status.UpdatedAt = now
	future.pendingStages = nil
	current := m.instances[future.pluginID]
	if current.generation == future.tombstone && m.latestGen[future.pluginID] == future.tombstone && !m.closing {
		if joined != nil {
			current.status.State = RuntimeStateDegraded
			current.status.Message = runtimeDegradedMessage
			current.status.StoppedAt = time.Time{}
		} else {
			current.status.State = RuntimeStateStopped
			current.status.Message = runtimeStoppedMessage
			current.status.StoppedAt = now
		}
		current.status.UpdatedAt = now
		m.instances[future.pluginID] = current
	}
	if joined == nil {
		future.runner = nil
		future.broker = nil
		future.pendingStarts = nil
		future.predecessors = nil
	}
	close(future.done)
	m.mu.Unlock()
}

func (m *RuntimeManager) waitRuntimeStop(future *runtimeStopFuture) (RuntimeStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	select {
	case <-future.done:
		m.mu.Lock()
		status := future.status
		err := future.err
		m.mu.Unlock()
		return status, err
	case <-ctx.Done():
		m.mu.Lock()
		select {
		case <-future.done:
			status := future.status
			err := future.err
			m.mu.Unlock()
			return status, err
		default:
		}
		current := m.instances[future.pluginID]
		future.status.State = RuntimeStateDegraded
		future.status.Message = runtimePendingMessage
		future.status.StoppedAt = time.Time{}
		future.status.UpdatedAt = time.Now().UTC()
		if current.generation == future.tombstone && m.latestGen[future.pluginID] == future.tombstone && !m.closing {
			current.status.State = RuntimeStateDegraded
			current.status.Message = runtimePendingMessage
			current.status.StoppedAt = time.Time{}
			current.status.UpdatedAt = time.Now().UTC()
			m.instances[future.pluginID] = current
		}
		status := future.status
		pending := runtimePendingStages(future.pendingStages)
		if len(pending) == 0 {
			pending = []string{"finalizing"}
		}
		m.mu.Unlock()
		return status, &RuntimeShutdownError{
			PluginID: future.pluginID, Stage: "shutdown-pending", PendingStages: pending, Err: ctx.Err(),
		}
	}
}

func runtimePendingStages(pending map[string]int) []string {
	stages := make([]string, 0, len(pending))
	for stage, count := range pending {
		if count > 0 {
			stages = append(stages, stage)
		}
	}
	slices.Sort(stages)
	return stages
}

func addRuntimeShutdownOwner[K comparable](owners map[K]map[string]struct{}, key K, pluginID string) {
	if owners[key] == nil {
		owners[key] = map[string]struct{}{}
	}
	owners[key][pluginID] = struct{}{}
}

func runtimeShutdownOwnerIDs(owners map[string]struct{}) []string {
	pluginIDs := make([]string, 0, len(owners))
	for pluginID := range owners {
		pluginIDs = append(pluginIDs, pluginID)
	}
	slices.Sort(pluginIDs)
	return pluginIDs
}

func boundedRuntimeStatusMessage(message string) string {
	const maxStatusMessageBytes = 160
	if len(message) <= maxStatusMessageBytes {
		return message
	}
	end := maxStatusMessageBytes
	for end > 0 && !utf8.ValidString(message[:end]) {
		end--
	}
	return message[:end]
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
			m.mu.Lock()
			select {
			case <-m.closeDone:
				err := m.closeErr
				m.mu.Unlock()
				return err
			default:
			}
			for id, epoch := range m.closeEpochs {
				inst := m.instances[id]
				if inst.generation == epoch && m.latestGen[id] == epoch && inst.status.State == RuntimeStateStopping {
					inst.status.State = RuntimeStateDegraded
					inst.status.Message = runtimePendingMessage
					inst.status.UpdatedAt = time.Now().UTC()
					m.instances[id] = inst
				}
			}
			pending := runtimePendingStages(m.closePending)
			if len(pending) == 0 {
				pending = []string{"finalizing"}
			}
			m.mu.Unlock()
			return &RuntimeShutdownError{Stage: "shutdown-pending", PendingStages: pending, Err: ctx.Err()}
		}
	}
	m.closing = true
	var pendingDone []runtimePendingClose
	closers := make(map[RunnerCloser]map[string]struct{})
	authorities := make(map[*generationAuthority]map[string]struct{})
	affected := make(map[string]struct{})
	for pluginID, attempts := range m.pendingStarts {
		affected[pluginID] = struct{}{}
		for _, pending := range attempts {
			if pending.cancel != nil {
				pending.cancel()
			}
			if pending.prepareDone != nil {
				pendingDone = append(pendingDone, runtimePendingClose{
					pluginID: pluginID, stage: "pending-starts", done: pending.prepareDone,
				})
			}
			if pending.cleanup != nil && pending.cleanup.done != nil {
				pendingDone = append(pendingDone, runtimePendingClose{
					pluginID: pluginID, stage: "pending-cleanup", done: pending.cleanup.done, cleanup: pending.cleanup,
				})
			}
			if closer, ok := pending.runner.(RunnerCloser); ok && closer != nil {
				addRuntimeShutdownOwner(closers, closer, pluginID)
			}
			if pending.broker != nil && pending.broker.authority != nil {
				pending.broker.authority.revoke()
				addRuntimeShutdownOwner(authorities, pending.broker.authority, pluginID)
			}
		}
		delete(m.pendingStarts, pluginID)
	}
	for _, runner := range m.runners {
		if closer, ok := runner.(RunnerCloser); ok && closer != nil {
			if _, exists := closers[closer]; !exists {
				closers[closer] = map[string]struct{}{}
			}
		}
	}
	for pluginID, inst := range m.instances {
		affected[pluginID] = struct{}{}
		if closer, ok := inst.runner.(RunnerCloser); ok && closer != nil {
			addRuntimeShutdownOwner(closers, closer, pluginID)
		}
		if inst.broker != nil && inst.broker.authority != nil {
			inst.broker.authority.revoke()
			addRuntimeShutdownOwner(authorities, inst.broker.authority, pluginID)
		}
	}
	var stopFutures []*runtimeStopFuture
	for pluginID, generations := range m.stopFutures {
		affected[pluginID] = struct{}{}
		for _, future := range generations {
			stopFutures = append(stopFutures, future)
			if closer, ok := future.runner.(RunnerCloser); ok && closer != nil {
				addRuntimeShutdownOwner(closers, closer, pluginID)
			}
			if future.broker != nil && future.broker.authority != nil {
				future.broker.authority.revoke()
				addRuntimeShutdownOwner(authorities, future.broker.authority, pluginID)
			}
			for _, pending := range future.pendingStarts {
				if closer, ok := pending.runner.(RunnerCloser); ok && closer != nil {
					addRuntimeShutdownOwner(closers, closer, pluginID)
				}
				if pending.broker != nil && pending.broker.authority != nil {
					pending.broker.authority.revoke()
					addRuntimeShutdownOwner(authorities, pending.broker.authority, pluginID)
				}
			}
		}
	}
	m.closeEpochs = make(map[string]uint64, len(affected))
	now := time.Now().UTC()
	for pluginID := range affected {
		m.nextGen++
		tombstone := m.nextGen
		m.latestGen[pluginID] = tombstone
		m.closeEpochs[pluginID] = tombstone
		inst, ok := m.instances[pluginID]
		if !ok {
			inst.status = RuntimeStatus{PluginID: pluginID}
		}
		inst.generation = tombstone
		inst.status.PluginID = pluginID
		inst.status.State = RuntimeStateStopping
		inst.status.Message = runtimeStoppingMessage
		inst.status.StoppedAt = time.Time{}
		inst.status.UpdatedAt = now
		inst.runner = nil
		inst.broker = nil
		m.instances[pluginID] = inst
	}
	m.closePending = map[string]int{}
	if len(closers) != 0 {
		m.closePending["runner-cleanup"] = len(closers)
	}
	for _, pending := range pendingDone {
		m.closePending[pending.stage]++
	}
	if len(stopFutures) != 0 {
		m.closePending["plugin-stops"] = len(stopFutures)
	}
	if len(authorities) != 0 {
		m.closePending["authority-drain"] = len(authorities)
	}
	m.mu.Unlock()
	for _, future := range stopFutures {
		future.start(m)
	}
	go m.finishClose(closers, pendingDone, stopFutures, authorities, m.closeEpochs)
	select {
	case <-m.closeDone:
		m.mu.Lock()
		err := m.closeErr
		m.mu.Unlock()
		return err
	case <-ctx.Done():
		m.mu.Lock()
		select {
		case <-m.closeDone:
			err := m.closeErr
			m.mu.Unlock()
			return err
		default:
		}
		for id, epoch := range m.closeEpochs {
			inst := m.instances[id]
			if inst.generation == epoch && m.latestGen[id] == epoch && inst.status.State == RuntimeStateStopping {
				inst.status.State = RuntimeStateDegraded
				inst.status.Message = runtimePendingMessage
				inst.status.UpdatedAt = time.Now().UTC()
				m.instances[id] = inst
			}
		}
		pending := runtimePendingStages(m.closePending)
		if len(pending) == 0 {
			pending = []string{"finalizing"}
		}
		m.mu.Unlock()
		return &RuntimeShutdownError{Stage: "shutdown-pending", PendingStages: pending, Err: ctx.Err()}
	}
}

func (m *RuntimeManager) finishClose(
	closers map[RunnerCloser]map[string]struct{},
	pendingDone []runtimePendingClose,
	stopFutures []*runtimeStopFuture,
	authorities map[*generationAuthority]map[string]struct{},
	epochs map[string]uint64,
) {
	results := make(chan runtimeShutdownPart, len(closers)+len(pendingDone)+len(stopFutures)+len(authorities))
	remaining := 0
	for closer, owners := range closers {
		remaining++
		go func(closer RunnerCloser, pluginIDs []string) {
			results <- runtimeShutdownPart{stage: "runner-cleanup", pluginIDs: pluginIDs, err: closer.StopAll(context.Background())}
		}(closer, runtimeShutdownOwnerIDs(owners))
	}
	for _, pending := range pendingDone {
		remaining++
		go func(pending runtimePendingClose) {
			<-pending.done
			var err error
			if pending.cleanup != nil {
				err = pending.cleanup.result()
			}
			results <- runtimeShutdownPart{
				stage: pending.stage, pluginIDs: []string{pending.pluginID}, err: err,
			}
		}(pending)
	}
	for _, future := range stopFutures {
		remaining++
		go func(future *runtimeStopFuture) {
			<-future.done
			results <- runtimeShutdownPart{stage: "plugin-stops", pluginIDs: []string{future.pluginID}, err: future.err}
		}(future)
	}
	for authority, owners := range authorities {
		remaining++
		go func(authority *generationAuthority, pluginIDs []string) {
			results <- runtimeShutdownPart{stage: "authority-drain", pluginIDs: pluginIDs, err: authority.wait(context.Background())}
		}(authority, runtimeShutdownOwnerIDs(owners))
	}
	var joined error
	pluginErrors := make(map[string]error)
	for range remaining {
		result := <-results
		joined = errors.Join(joined, result.err)
		for _, pluginID := range result.pluginIDs {
			pluginErrors[pluginID] = errors.Join(pluginErrors[pluginID], result.err)
		}
		m.mu.Lock()
		m.closePending[result.stage]--
		if m.closePending[result.stage] == 0 {
			delete(m.closePending, result.stage)
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.closeErr = joined
	now := time.Now().UTC()
	for pluginID, epoch := range epochs {
		inst := m.instances[pluginID]
		if inst.generation != epoch || m.latestGen[pluginID] != epoch {
			continue
		}
		if pluginErrors[pluginID] != nil {
			inst.status.State = RuntimeStateDegraded
			inst.status.Message = runtimeDegradedMessage
			inst.status.StoppedAt = time.Time{}
		} else {
			inst.status.State = RuntimeStateStopped
			inst.status.Message = runtimeStoppedMessage
			inst.status.StoppedAt = now
		}
		inst.status.UpdatedAt = now
		m.instances[pluginID] = inst
	}
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
