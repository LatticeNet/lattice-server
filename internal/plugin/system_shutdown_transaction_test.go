package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestSystemRunnerStopTimeoutReturnsTypedSnapshotAndRetainsGeneration(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "generation-7")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := shutdownTestState("p.pending", 7, workDir)
	st.refs = 1
	st.refsDone = make(chan struct{})
	r := &SystemRunner{st: map[string]map[uint64]*systemPluginState{st.pluginID: {st.generation: st}}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Stop(ctx, RunnerStopRequest{PluginID: st.pluginID, Generation: st.generation})
	var cleanupErr *GenerationCleanupError
	if !errors.As(err, &cleanupErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop error=%v typed=%+v", err, cleanupErr)
	}
	if cleanupErr.PluginID != st.pluginID || cleanupErr.Generation != st.generation || cleanupErr.Stage != "cleanup-pending" {
		t.Fatalf("snapshot=%+v", cleanupErr)
	}
	if !slices.Contains(cleanupErr.PendingStages, "invocation-references") {
		t.Fatalf("pending stages=%v", cleanupErr.PendingStages)
	}
	if r.st[st.pluginID][st.generation] != st {
		t.Fatal("pending generation ownership was dropped")
	}
	if _, err := os.Stat(workDir); err != nil {
		t.Fatalf("workdir removed before refs drained: %v", err)
	}

	r.mu.Lock()
	st.refs = 0
	close(st.refsDone)
	r.mu.Unlock()
	if err := r.Stop(t.Context(), RunnerStopRequest{PluginID: st.pluginID, Generation: st.generation}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(workDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workdir disposition err=%v", err)
	}
}

func TestSystemRunnerStopAllBroadcastsAuthorityBeforeWaiting(t *testing.T) {
	r := &SystemRunner{st: map[string]map[uint64]*systemPluginState{}}
	for i, id := range []string{"p.one", "p.two"} {
		st := shutdownTestState(id, uint64(i+1), t.TempDir())
		st.refs = 1
		st.refsDone = make(chan struct{})
		r.st[id] = map[uint64]*systemPluginState{st.generation: st}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = r.StopAll(ctx)
	for id, generations := range r.st {
		for _, st := range generations {
			if _, _, err := st.broker.authority.acquire(context.Background()); !errors.Is(err, errGenerationRevoked) {
				t.Fatalf("authority for %s was not broadcast-revoked: %v", id, err)
			}
		}
	}
}

func TestRuntimeManagerCloseTimeoutIsDegradedUntilSharedPhysicalFutureCompletes(t *testing.T) {
	runner := &shutdownBlockingRunner{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	loaded := testRuntimeLoaded("close-physical.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.Close(ctx)
	var shutdownErr *RuntimeShutdownError
	if !errors.As(err, &shutdownErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Close error=%v typed=%+v", err, shutdownErr)
	}
	status, _ := m.Status(loaded.Manifest.ID)
	if status.State != RuntimeStateDegraded || !status.StoppedAt.IsZero() {
		t.Fatalf("timed-out status=%+v", status)
	}
	select {
	case <-m.closeDone:
		t.Fatal("closeDone closed before physical runner cleanup")
	default:
	}
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("StopAll was not started")
	}
	close(runner.release)
	if err := m.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, _ = m.Status(loaded.Manifest.ID)
	if status.State != RuntimeStateStopped || status.StoppedAt.IsZero() || runner.calls != 1 {
		t.Fatalf("completed status=%+v calls=%d", status, runner.calls)
	}
}

func TestRuntimeManagerConcurrentCloseObserversShareOnePhysicalFuture(t *testing.T) {
	runner := &shutdownBlockingRunner{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	if _, err := m.Start(t.Context(), testRuntimeLoaded("close-observers.bundle")); err != nil {
		t.Fatal(err)
	}

	const observers = 32
	results := make(chan error, observers)
	var ready sync.WaitGroup
	ready.Add(observers)
	for range observers {
		go func() {
			ready.Done()
			results <- m.Close(context.Background())
		}()
	}
	ready.Wait()
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("StopAll was not started")
	}
	close(runner.release)
	for range observers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if runner.calls != 1 {
		t.Fatalf("StopAll calls=%d want 1", runner.calls)
	}
}

func shutdownTestState(pluginID string, generation uint64, workDir string) *systemPluginState {
	authority := newGenerationAuthority()
	broker := &Broker{}
	broker.attachAuthority(authority)
	refsDone := make(chan struct{})
	close(refsDone)
	rootCtx, rootCancel := context.WithCancel(context.Background())
	return &systemPluginState{
		pluginID: pluginID, generation: generation, workDir: workDir,
		broker: broker, pool: newSystemPool(1, time.Hour, generation),
		admitted: true, cleanupDone: make(chan struct{}), refsDone: refsDone,
		v1Active: map[uint64]context.CancelFunc{}, rootCtx: rootCtx, rootCancel: rootCancel,
	}
}

type shutdownBlockingRunner struct {
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
	calls   int
}

func (r *shutdownBlockingRunner) Name() string { return "shutdown-blocking" }
func (r *shutdownBlockingRunner) Start(context.Context, RunnerStartRequest) (RunnerStartResult, error) {
	return RunnerStartResult{Message: "armed"}, nil
}
func (r *shutdownBlockingRunner) Stop(context.Context, RunnerStopRequest) error { return nil }
func (r *shutdownBlockingRunner) StopAll(context.Context) error {
	r.mu.Lock()
	r.calls++
	if r.calls == 1 {
		close(r.entered)
	}
	r.mu.Unlock()
	<-r.release
	return nil
}
