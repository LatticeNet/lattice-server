package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRuntimeManagerArmsLoadedPluginWithoutExecutingArtifact(t *testing.T) {
	m := NewRuntimeManager(HostServices{})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "ops.bundle",
			Name:         "Ops",
			Type:         TypeSystem,
			Capabilities: []string{"node:read", "log:write"},
		},
		Capabilities: []string{"log:write", "node:read"},
		BundlePath:   "/plugins/ops",
	}

	rt, err := m.Start(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if rt.PluginID != "ops.bundle" || rt.State != RuntimeStateArmed || rt.StartedAt.IsZero() || rt.UpdatedAt.IsZero() {
		t.Fatalf("unexpected runtime state: %+v", rt)
	}
	if rt.Runner != "noop" {
		t.Fatalf("expected default noop runner, got %+v", rt)
	}
	encoded, err := json.Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "bundle_path") || strings.Contains(string(encoded), "/plugins/ops") {
		t.Fatalf("runtime status must not expose bundle path: %s", encoded)
	}
	if !m.IsArmed("ops.bundle") {
		t.Fatal("expected plugin to be armed")
	}
}

func TestRuntimeManagerRejectsInvalidLoadedPlugin(t *testing.T) {
	m := NewRuntimeManager(HostServices{})
	_, err := m.Start(context.Background(), Loaded{
		Manifest: Manifest{
			ID:           "bad.bundle",
			Name:         "Bad",
			Type:         TypeWorker,
			Capabilities: []string{"network:apply"},
		},
		Capabilities: []string{"network:apply"},
	})
	if err == nil {
		t.Fatal("expected invalid loaded manifest to be rejected")
	}
	if m.IsArmed("bad.bundle") {
		t.Fatal("invalid plugin must not be armed")
	}
}

func TestRuntimeManagerUsesRegisteredRunnerWithBrokerAndTimeout(t *testing.T) {
	runner := &recordingRunner{name: "system-safe"}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Services:     HostServices{},
		StartTimeout: 50 * time.Millisecond,
		Runners:      map[string]Runner{TypeSystem: runner},
	})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "ops.bundle",
			Name:         "Ops",
			Type:         TypeSystem,
			Capabilities: []string{"log:write", "node:read"},
		},
		Capabilities: []string{"log:write", "node:read"},
	}

	rt, err := m.Start(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Runner != "system-safe" || rt.Message != "system runner armed" {
		t.Fatalf("unexpected runtime status: %+v", rt)
	}
	if runner.startCalls != 1 || runner.startReq.PluginID != "ops.bundle" {
		t.Fatalf("runner did not receive start request: calls=%d req=%+v", runner.startCalls, runner.startReq)
	}
	if runner.startReq.Broker == nil || !runner.startReq.Broker.HasCapability("log:write") || runner.startReq.Broker.HasCapability("kv:write") {
		t.Fatalf("runner did not receive a capability-scoped broker: %+v", runner.startReq.Broker)
	}
	if _, ok := runner.startDeadline.Deadline(); !ok {
		t.Fatal("runner start context must carry a deadline")
	}

	if _, err := m.Stop("ops.bundle", "operator disabled"); err != nil {
		t.Fatal(err)
	}
	if runner.stopCalls != 1 || runner.stopReq.PluginID != "ops.bundle" || runner.stopReq.Reason != "operator disabled" {
		t.Fatalf("runner did not receive stop request: calls=%d req=%+v", runner.stopCalls, runner.stopReq)
	}
	if _, err := m.Stop("ops.bundle", "operator disabled again"); err != nil {
		t.Fatal(err)
	}
	if runner.stopCalls != 1 {
		t.Fatalf("stopped runtime should not retain the runner handle, calls=%d", runner.stopCalls)
	}
}

func TestRuntimeManagerRecordsFailedHealthWhenRunnerStartFails(t *testing.T) {
	runner := &recordingRunner{name: "broken", startErr: errors.New("runner refused")}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner},
	})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "broken.bundle",
			Name:         "Broken",
			Type:         TypeSystem,
			Capabilities: []string{"node:read"},
		},
		Capabilities: []string{"node:read"},
	}
	rt, err := m.Start(context.Background(), loaded)
	if err == nil {
		t.Fatal("expected runner start failure")
	}
	if rt.State != RuntimeStateFailed || rt.Runner != "broken" || !strings.Contains(rt.Message, "runner refused") {
		t.Fatalf("unexpected failed runtime status: %+v err=%v", rt, err)
	}
	got, ok := m.Status("broken.bundle")
	if !ok || got.State != RuntimeStateFailed || m.IsArmed("broken.bundle") {
		t.Fatalf("failed status should be retained but not armed: ok=%v status=%+v", ok, got)
	}
}

func TestRuntimeManagerFailedStopDetachesHostAccess(t *testing.T) {
	// S4: when a plugin's Stop hook fails, the manager must still detach the
	// broker and runner — a plugin we have decided to disable is no longer trusted
	// with host access regardless of whether its Stop hook succeeded. We observe
	// the detach behaviorally: a second Stop must NOT re-invoke the runner, because
	// the runner handle was cleared on the failed first Stop.
	runner := &failStopRunner{name: "fails-stop", stopErr: errors.New("stop hook refused")}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner},
	})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "stuck.bundle",
			Name:         "Stuck",
			Type:         TypeSystem,
			Capabilities: []string{"node:read"},
		},
		Capabilities: []string{"node:read"},
	}
	if _, err := m.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}

	rt, err := m.Stop("stuck.bundle", "operator disabled")
	if err == nil {
		t.Fatal("expected the failing stop hook to surface an error")
	}
	if rt.State != RuntimeStateFailed {
		t.Fatalf("failed stop should mark state failed, got %+v", rt)
	}
	if runner.stopCalls != 1 {
		t.Fatalf("first stop should call the runner once, got %d", runner.stopCalls)
	}

	// Second stop must be a no-op on the runner: a failed stop already detached the
	// runner handle, proving host access is no longer armed for this plugin.
	if _, err := m.Stop("stuck.bundle", "operator disabled again"); err != nil {
		t.Fatalf("second stop after a failed stop should succeed cleanly, got %v", err)
	}
	if runner.stopCalls != 1 {
		t.Fatalf("failed stop must detach the runner; runner re-invoked, stopCalls=%d", runner.stopCalls)
	}
	if m.IsArmed("stuck.bundle") {
		t.Fatal("plugin must not be armed after a failed stop")
	}
}

func TestRuntimeManagerStopDoesNotClobberNewStart(t *testing.T) {
	runner := &blockingStopRunner{
		stopEntered: make(chan struct{}),
		releaseStop: make(chan struct{}),
	}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner},
	})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "ops.bundle",
			Name:         "Ops",
			Type:         TypeSystem,
			Capabilities: []string{"node:read"},
		},
		Capabilities: []string{"node:read"},
	}
	if _, err := m.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}

	stopDone := make(chan error, 1)
	go func() {
		_, err := m.Stop("ops.bundle", "old stop")
		stopDone <- err
	}()
	<-runner.stopEntered

	if _, err := m.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	close(runner.releaseStop)
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}

	got, ok := m.Status("ops.bundle")
	if !ok || got.State != RuntimeStateArmed {
		t.Fatalf("stale stop must not clobber a newer start: ok=%v status=%+v", ok, got)
	}
}

func TestRuntimeManagerPinsGenerationBeforeReplacementRetiresIt(t *testing.T) {
	runner := newTransactionalTestRunner()
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	loaded := testRuntimeLoaded("pin.bundle")
	if _, err := m.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	runner.blockAcquire = make(chan struct{})
	runner.acquireEntered = make(chan struct{})
	invokeDone := make(chan InvokeResponse, 1)
	go func() {
		resp, _ := m.Invoke(context.Background(), loaded.Manifest.ID, "old", nil)
		invokeDone <- resp
	}()
	<-runner.acquireEntered
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	close(runner.blockAcquire)
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
	resp := <-invokeDone
	if string(resp.Result) != `{"generation":1}` {
		t.Fatalf("pinned invocation switched generations: %s", resp.Result)
	}
	resp, err := m.Invoke(context.Background(), loaded.Manifest.ID, "new", nil)
	if err != nil || string(resp.Result) != `{"generation":2}` {
		t.Fatalf("new invocation did not use committed generation: resp=%s err=%v", resp.Result, err)
	}
}

func TestRuntimeManagerCloseWaitsPendingPrepareAndIsIdempotent(t *testing.T) {
	runner := newTransactionalTestRunner()
	runner.blockPrepare = make(chan struct{})
	runner.prepareEntered = make(chan struct{})
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), testRuntimeLoaded("close.bundle")); startDone <- err }()
	<-runner.prepareEntered
	closeDone := make(chan error, 2)
	go func() { closeDone <- m.Close(context.Background()) }()
	go func() { closeDone <- m.Close(context.Background()) }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before pending Prepare exited: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(runner.blockPrepare)
	_ = <-startDone
	for range 2 {
		if err := <-closeDone; err != nil {
			t.Fatal(err)
		}
	}
	if runner.stopAllCalls != 1 {
		t.Fatalf("StopAll calls=%d want 1", runner.stopAllCalls)
	}
	if _, err := m.Start(context.Background(), testRuntimeLoaded("after-close.bundle")); err == nil {
		t.Fatal("Start succeeded after Close")
	}
}

func testRuntimeLoaded(id string) Loaded {
	return Loaded{Manifest: Manifest{ID: id, Name: id, Type: TypeSystem, Capabilities: []string{"node:read"}}, Capabilities: []string{"node:read"}}
}

type transactionalTestRunner struct {
	mu             sync.Mutex
	prepared       map[uint64]bool
	active         map[uint64]bool
	retired        map[uint64]bool
	blockPrepare   chan struct{}
	prepareEntered chan struct{}
	blockAcquire   chan struct{}
	acquireEntered chan struct{}
	stopAllCalls   int
}

func newTransactionalTestRunner() *transactionalTestRunner {
	return &transactionalTestRunner{prepared: map[uint64]bool{}, active: map[uint64]bool{}, retired: map[uint64]bool{}}
}
func (r *transactionalTestRunner) Name() string { return "transactional-test" }
func (r *transactionalTestRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	result, err := r.Prepare(ctx, req)
	if err == nil {
		err = r.ActivateGeneration(req.PluginID, req.Generation)
	}
	return result, err
}
func (r *transactionalTestRunner) Prepare(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	if r.prepareEntered != nil {
		select {
		case <-r.prepareEntered:
		default:
			close(r.prepareEntered)
		}
	}
	if r.blockPrepare != nil {
		<-r.blockPrepare
	}
	r.mu.Lock()
	r.prepared[req.Generation] = true
	r.mu.Unlock()
	return RunnerStartResult{Message: "prepared"}, ctx.Err()
}
func (r *transactionalTestRunner) ActivateGeneration(_ string, generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.prepared[generation] {
		return errors.New("not prepared")
	}
	r.active[generation] = true
	return nil
}
func (r *transactionalTestRunner) AbortGeneration(_ context.Context, _ string, generation uint64) error {
	r.mu.Lock()
	delete(r.prepared, generation)
	delete(r.active, generation)
	r.mu.Unlock()
	return nil
}
func (r *transactionalTestRunner) RetireGeneration(_ context.Context, _ string, generation uint64) error {
	r.mu.Lock()
	r.active[generation] = false
	r.retired[generation] = true
	r.mu.Unlock()
	return nil
}
func (r *transactionalTestRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	r.mu.Lock()
	for gen := range r.active {
		if req.Generation == 0 || gen <= req.Generation {
			r.active[gen] = false
		}
	}
	r.mu.Unlock()
	return ctx.Err()
}
func (r *transactionalTestRunner) StopAll(context.Context) error {
	r.mu.Lock()
	r.stopAllCalls++
	for gen := range r.active {
		r.active[gen] = false
	}
	r.mu.Unlock()
	return nil
}
func (r *transactionalTestRunner) Invoke(context.Context, InvokeRequest) (InvokeResponse, error) {
	return InvokeResponse{}, errors.New("lease required")
}
func (r *transactionalTestRunner) AcquireInvocation(_ string, generation uint64) (InvocationGenerationLease, error) {
	if r.acquireEntered != nil {
		select {
		case <-r.acquireEntered:
		default:
			close(r.acquireEntered)
		}
	}
	if r.blockAcquire != nil {
		<-r.blockAcquire
	}
	r.mu.Lock()
	active := r.active[generation]
	r.mu.Unlock()
	if !active {
		return nil, errors.New("not active")
	}
	return transactionalTestLease{generation: generation}, nil
}

type transactionalTestLease struct{ generation uint64 }

func (l transactionalTestLease) Invoke(context.Context, InvokeRequest) (InvokeResponse, error) {
	return InvokeResponse{OK: true, Result: json.RawMessage(fmt.Sprintf(`{"generation":%d}`, l.generation))}, nil
}
func (transactionalTestLease) Release() {}

func TestRuntimeManagerPassesInvocationBudgetToRunner(t *testing.T) {
	runner := &recordingInvokeRunner{}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner},
	})
	loaded := Loaded{
		Manifest: Manifest{
			ID: "budget.bundle", Name: "Budget", Type: TypeSystem,
			Capabilities: []string{"node:read"},
		},
		Capabilities: []string{"node:read"},
		BundlePath:   t.TempDir(),
	}
	if _, err := m.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	budget := &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 2 << 20, StderrBytes: 64 << 10, HostCalls: 0}
	resp, err := m.InvokeConstrained(context.Background(), loaded.Manifest.ID, "call", json.RawMessage(`{"ok":true}`), InvokeConstraints{
		Budget:      budget,
		BudgetLabel: "budget.bundle/list",
	})
	if err != nil || !resp.OK {
		t.Fatalf("InvokeConstrained: resp=%+v err=%v", resp, err)
	}
	if runner.invokeReq.Constraints.Budget != budget || runner.invokeReq.Constraints.BudgetLabel != "budget.bundle/list" {
		t.Fatalf("budget constraints did not reach runner: %+v", runner.invokeReq.Constraints)
	}
}

func TestRuntimeManagerStopAndSnapshotAreSafe(t *testing.T) {
	m := NewRuntimeManager(HostServices{})
	loaded := Loaded{
		Manifest: Manifest{
			ID:           "log.bundle",
			Name:         "Log",
			Type:         TypeSystem,
			Capabilities: []string{"log:write", "worker:route"},
		},
		Capabilities: []string{"log:write", "worker:route"},
	}
	if _, err := m.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	first := m.Snapshot()
	if got := first["log.bundle"]; got.State != RuntimeStateArmed {
		t.Fatalf("expected armed snapshot, got %+v", got)
	}
	delete(first, "log.bundle")
	if !m.IsArmed("log.bundle") {
		t.Fatal("mutating snapshot must not mutate manager")
	}

	stopped, err := m.Stop("log.bundle", "operator disabled plugin")
	if err != nil {
		t.Fatal(err)
	}
	if stopped.State != RuntimeStateStopped || stopped.Message != "operator disabled plugin" || stopped.StoppedAt.IsZero() {
		t.Fatalf("unexpected stopped runtime: %+v", stopped)
	}
	if m.IsArmed("log.bundle") {
		t.Fatal("stopped plugin must not remain armed")
	}
}

type recordingRunner struct {
	name          string
	startErr      error
	startCalls    int
	stopCalls     int
	startReq      RunnerStartRequest
	stopReq       RunnerStopRequest
	startDeadline context.Context
}

func (r *recordingRunner) Name() string {
	return r.name
}

func (r *recordingRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	r.startCalls++
	r.startReq = req
	r.startDeadline = ctx
	if r.startErr != nil {
		return RunnerStartResult{}, r.startErr
	}
	return RunnerStartResult{Message: "system runner armed"}, nil
}

func (r *recordingRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	r.stopCalls++
	r.stopReq = req
	return nil
}

type failStopRunner struct {
	name      string
	stopErr   error
	stopCalls int
}

func (r *failStopRunner) Name() string {
	return r.name
}

func (r *failStopRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	return RunnerStartResult{Message: "armed"}, ctx.Err()
}

func (r *failStopRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	r.stopCalls++
	return r.stopErr
}

type blockingStopRunner struct {
	stopEntered chan struct{}
	releaseStop chan struct{}
}

func (r *blockingStopRunner) Name() string {
	return "blocking"
}

func (r *blockingStopRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	return RunnerStartResult{Message: "blocking runner armed"}, ctx.Err()
}

func (r *blockingStopRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	close(r.stopEntered)
	select {
	case <-r.releaseStop:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type recordingInvokeRunner struct {
	invokeReq InvokeRequest
}

func (r *recordingInvokeRunner) Name() string {
	return "recording-invoker"
}

func (r *recordingInvokeRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	return RunnerStartResult{Message: "recording invoker armed"}, ctx.Err()
}

func (r *recordingInvokeRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	return ctx.Err()
}

func (r *recordingInvokeRunner) Invoke(ctx context.Context, req InvokeRequest) (InvokeResponse, error) {
	r.invokeReq = req
	return InvokeResponse{OK: true, Result: json.RawMessage(`{"recorded":true}`)}, ctx.Err()
}
