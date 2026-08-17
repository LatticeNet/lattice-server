package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

func TestSystemRunnerStopBroadcastsEverySelectedGenerationBeforeWaiting(t *testing.T) {
	r := &SystemRunner{st: map[string]map[uint64]*systemPluginState{"p.multi": {}}}
	for generation := uint64(1); generation <= 2; generation++ {
		st := shutdownTestState("p.multi", generation, t.TempDir())
		st.refs = 1
		st.refsDone = make(chan struct{})
		r.st[st.pluginID][generation] = st
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = r.Stop(ctx, RunnerStopRequest{PluginID: "p.multi", Generation: 2})
	for generation, st := range r.st["p.multi"] {
		if _, _, err := st.broker.authority.acquire(context.Background()); !errors.Is(err, errGenerationRevoked) {
			t.Fatalf("generation %d authority was not broadcast-revoked: %v", generation, err)
		}
	}
}

func TestSystemRunnerAbortTimeoutJoinsSameFutureAndRemovesOnce(t *testing.T) {
	st := shutdownTestState("p.abort", 3, t.TempDir())
	st.refs = 1
	st.refsDone = make(chan struct{})
	var removeCalls atomic.Int32
	r := &SystemRunner{
		st:        map[string]map[uint64]*systemPluginState{st.pluginID: {st.generation: st}},
		removeAll: func(string) error { removeCalls.Add(1); return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.AbortGeneration(ctx, st.pluginID, st.generation)
	var cleanupErr *GenerationCleanupError
	if !errors.As(err, &cleanupErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("AbortGeneration error=%v typed=%+v", err, cleanupErr)
	}
	r.mu.Lock()
	st.refs = 0
	close(st.refsDone)
	r.mu.Unlock()
	if err := r.AbortGeneration(t.Context(), st.pluginID, st.generation); err != nil {
		t.Fatal(err)
	}
	if removeCalls.Load() != 1 {
		t.Fatalf("remove calls=%d want 1", removeCalls.Load())
	}
}

func TestSystemRunnerConcurrentStopObserversReuseGenerationFuture(t *testing.T) {
	st := shutdownTestState("p.concurrent", 4, t.TempDir())
	st.refs = 1
	st.refsDone = make(chan struct{})
	var removeCalls atomic.Int32
	r := &SystemRunner{
		st:        map[string]map[uint64]*systemPluginState{st.pluginID: {st.generation: st}},
		removeAll: func(string) error { removeCalls.Add(1); return nil },
	}
	const observers = 32
	results := make(chan error, observers)
	for i := 0; i < observers; i++ {
		if i%2 == 0 {
			go func() {
				results <- r.Stop(context.Background(), RunnerStopRequest{PluginID: st.pluginID, Generation: st.generation})
			}()
		} else {
			go func() { results <- r.StopAll(context.Background()) }()
		}
	}
	deadline := time.After(time.Second)
	for {
		_, release, err := st.broker.authority.acquire(context.Background())
		if errors.Is(err, errGenerationRevoked) {
			break
		}
		if release != nil {
			release()
		}
		select {
		case <-deadline:
			t.Fatal("cleanup was not broadcast")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	r.mu.Lock()
	st.refs = 0
	close(st.refsDone)
	r.mu.Unlock()
	for range observers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if removeCalls.Load() != 1 {
		t.Fatalf("remove calls=%d want 1", removeCalls.Load())
	}
}

func TestSystemRunnerForceUpgradeRetainsCanonicalPoolFuture(t *testing.T) {
	st := shutdownTestState("p.force-upgrade", 5, t.TempDir())
	st.forceAbort = true
	st.pool.superStart = true
	st.pool.superDone = make(chan struct{})
	authorityCtx, releaseAuthority, err := st.broker.authority.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var removeCalls atomic.Int32
	r := &SystemRunner{
		st:        map[string]map[uint64]*systemPluginState{st.pluginID: {st.generation: st}},
		removeAll: func(string) error { removeCalls.Add(1); return nil },
	}
	r.mu.Lock()
	st.cleanupRequested = true
	st.cleanupArmed = true
	r.maybeStartCleanupLocked(st)
	r.mu.Unlock()
	deadline := time.After(time.Second)
	for {
		r.mu.Lock()
		future := st.poolFuture
		r.mu.Unlock()
		if future != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cleanup did not capture the pool-owned force future")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, _, err := st.broker.authority.acquire(context.Background()); !errors.Is(err, errGenerationRevoked) {
		t.Fatalf("force cleanup did not revoke authority before waiting: %v", err)
	}
	select {
	case <-authorityCtx.Done():
	default:
		t.Fatal("force cleanup did not cancel acquired authority before cleanup completion")
	}
	select {
	case <-st.cleanupDone:
		t.Fatal("cleanup completed before authority and pool supervisor drained")
	default:
	}
	if removeCalls.Load() != 0 {
		t.Fatal("workdir removed while force cleanup was pending")
	}
	releaseAuthority()
	close(st.pool.superDone)
	select {
	case <-st.cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after authority and pool drained")
	}
	if removeCalls.Load() != 1 {
		t.Fatalf("remove calls=%d want 1", removeCalls.Load())
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
	type closeObservation struct {
		short bool
		err   error
	}
	results := make(chan closeObservation, observers)
	var ready sync.WaitGroup
	ready.Add(observers)
	start := make(chan struct{})
	for i := 0; i < observers; i++ {
		go func(short bool) {
			ready.Done()
			<-start
			ctx := context.Background()
			if short {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			results <- closeObservation{short: short, err: m.Close(ctx)}
		}(i%2 == 0)
	}
	ready.Wait()
	close(start)
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("StopAll was not started")
	}
	for range observers / 2 {
		result := <-results
		if !result.short || !errors.Is(result.err, context.Canceled) {
			t.Fatalf("pre-completion observer=%+v want short canceled", result)
		}
	}
	close(runner.release)
	for range observers / 2 {
		result := <-results
		if result.short || result.err != nil {
			t.Fatalf("terminal observer=%+v want long success", result)
		}
	}
	if runner.calls != 1 {
		t.Fatalf("StopAll calls=%d want 1", runner.calls)
	}
}

func TestRuntimeManagerStopTimeoutReusesPhysicalFuture(t *testing.T) {
	runner := &shutdownBlockingStopRunner{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("stop-future.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}

	status, err := m.Stop(loaded.Manifest.ID, "operator disabled")
	var shutdownErr *RuntimeShutdownError
	if !errors.As(err, &shutdownErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Stop error=%v typed=%+v", err, shutdownErr)
	}
	if status.State != RuntimeStateDegraded || !status.StoppedAt.IsZero() {
		t.Fatalf("first Stop status=%+v", status)
	}
	if !slices.Equal(shutdownErr.PendingStages, []string{"runner-cleanup"}) {
		t.Fatalf("first Stop pending stages=%v", shutdownErr.PendingStages)
	}
	status, err = m.Stop(loaded.Manifest.ID, "operator disabled again")
	if !errors.As(err, &shutdownErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Stop error=%v typed=%+v", err, shutdownErr)
	}
	if calls := runner.calls.Load(); calls != 1 {
		t.Fatalf("second Stop started another physical cleanup: calls=%d", calls)
	}

	close(runner.release)
	status, err = m.Stop(loaded.Manifest.ID, "join completed stop")
	if err != nil {
		t.Fatal(err)
	}
	if status.State != RuntimeStateStopped || status.StoppedAt.IsZero() {
		t.Fatalf("completed Stop status=%+v", status)
	}
	if calls := runner.calls.Load(); calls != 1 {
		t.Fatalf("completed Stop restarted cleanup: calls=%d", calls)
	}
	m.mu.Lock()
	future := m.stopFutures[loaded.Manifest.ID][m.latestGen[loaded.Manifest.ID]]
	m.mu.Unlock()
	if future == nil || future.runner != nil || future.broker != nil || future.pendingStarts != nil || future.predecessors != nil {
		t.Fatalf("clean terminal future retained strong ownership: %+v", future)
	}
}

func TestRuntimeManagerTerminalStopResultWinsTimeoutRace(t *testing.T) {
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{})
	m.timeout = 0
	status := RuntimeStatus{
		PluginID: "terminal-race.bundle", State: RuntimeStateStopped,
		Message: runtimeStoppedMessage, StoppedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	done := make(chan struct{})
	close(done)
	future := &runtimeStopFuture{pluginID: status.PluginID, tombstone: 1, done: done, status: status}
	m.instances[status.PluginID] = runtimeInstance{generation: 1, status: status}
	m.latestGen[status.PluginID] = 1
	for i := 0; i < 100; i++ {
		got, err := m.waitRuntimeStop(future)
		if err != nil || got.State != RuntimeStateStopped || got.StoppedAt.IsZero() {
			t.Fatalf("iteration %d terminal result lost: status=%+v err=%v", i, got, err)
		}
	}
}

func TestRuntimeManagerSecondStopAfterPendingStartCreatesNewEpochAndJoinsPredecessor(t *testing.T) {
	runner := newStopEpochRunner()
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 50 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("stop-epoch.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(loaded.Manifest.ID, "first stop"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Stop error=%v want deadline", err)
	}
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	<-runner.secondStartEntered
	type stopResult struct {
		status RuntimeStatus
		err    error
	}
	secondDone := make(chan stopResult, 1)
	go func() {
		status, err := m.Stop(loaded.Manifest.ID, "second stop")
		secondDone <- stopResult{status: status, err: err}
	}()
	deadline := time.After(time.Second)
	var firstEpoch, secondEpoch uint64
	for {
		m.mu.Lock()
		if len(m.stopFutures[loaded.Manifest.ID]) == 2 {
			for epoch := range m.stopFutures[loaded.Manifest.ID] {
				if firstEpoch == 0 || epoch < firstEpoch {
					secondEpoch = firstEpoch
					firstEpoch = epoch
				} else {
					secondEpoch = epoch
				}
			}
		}
		m.mu.Unlock()
		if secondEpoch != 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("second Stop did not allocate a new stop epoch")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if firstEpoch == secondEpoch {
		t.Fatalf("stop epochs were reused: %d", firstEpoch)
	}
	if _, _, err := runner.secondBroker.authority.acquire(context.Background()); !errors.Is(err, errGenerationRevoked) {
		t.Fatalf("second Stop did not revoke pending broker authority: %v", err)
	}
	close(runner.firstStopRelease)
	close(runner.secondStartRelease)
	if err := <-startDone; err == nil {
		t.Fatal("higher pending Start unexpectedly committed")
	}
	result := <-secondDone
	if result.err != nil || result.status.State != RuntimeStateStopped || result.status.StoppedAt.IsZero() {
		t.Fatalf("second Stop result=%+v err=%v", result.status, result.err)
	}
	m.mu.Lock()
	latest := m.latestGen[loaded.Manifest.ID]
	secondFuture := m.stopFutures[loaded.Manifest.ID][secondEpoch]
	m.mu.Unlock()
	if latest != secondEpoch || secondFuture == nil || runner.stopCalls.Load() != 2 {
		t.Fatalf("latest=%d second=%d future=%p stopCalls=%d", latest, secondEpoch, secondFuture, runner.stopCalls.Load())
	}
}

func TestRuntimeManagerOldStopCompletionDoesNotOverwriteHigherPendingStart(t *testing.T) {
	runner := newStopEpochRunner()
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("pending-generation-guard.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(loaded.Manifest.ID, "old stop"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("old Stop error=%v want deadline", err)
	}
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	<-runner.secondStartEntered
	close(runner.firstStopRelease)
	m.mu.Lock()
	var oldFuture *runtimeStopFuture
	for _, future := range m.stopFutures[loaded.Manifest.ID] {
		oldFuture = future
	}
	m.mu.Unlock()
	<-oldFuture.done
	status, _ := m.Status(loaded.Manifest.ID)
	if status.State == RuntimeStateStopped || !status.StoppedAt.IsZero() {
		t.Fatalf("old stop overwrote higher pending generation: %+v", status)
	}
	close(runner.secondStartRelease)
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(loaded.Manifest.ID, "cleanup"); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeManagerNewerArmedStopWaitsForPredecessorFuture(t *testing.T) {
	runner := newArmedPredecessorRunner()
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("armed-predecessor.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(loaded.Manifest.ID, "T1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("T1 Stop error=%v want deadline", err)
	}
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	type stopResult struct {
		status RuntimeStatus
		err    error
	}
	t2Done := make(chan stopResult, 1)
	go func() {
		status, err := m.Stop(loaded.Manifest.ID, "T2")
		t2Done <- stopResult{status: status, err: err}
	}()
	<-runner.secondStopEntered
	close(runner.secondStopRelease)
	deadline := time.After(time.Second)
	for {
		m.mu.Lock()
		t2Epoch := m.latestGen[loaded.Manifest.ID]
		t2Future := m.stopFutures[loaded.Manifest.ID][t2Epoch]
		runnerConsumed := t2Future != nil && t2Future.pendingStages["runner-cleanup"] == 0 && t2Future.pendingStages["predecessor-stops"] == 1
		m.mu.Unlock()
		if runnerConsumed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("T2 did not consume its own runner cleanup while predecessor remained pending")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case result := <-t2Done:
		t.Fatalf("T2 returned before predecessor T1: status=%+v err=%v", result.status, result.err)
	default:
	}
	status, _ := m.Status(loaded.Manifest.ID)
	if status.State == RuntimeStateStopped || !status.StoppedAt.IsZero() {
		t.Fatalf("T2 published stopped before predecessor T1: %+v", status)
	}
	close(runner.firstStopRelease)
	result := <-t2Done
	if result.err != nil || result.status.State != RuntimeStateStopped || result.status.StoppedAt.IsZero() {
		t.Fatalf("T2 terminal result=%+v err=%v", result.status, result.err)
	}
	if runner.stopCalls.Load() != 2 {
		t.Fatalf("runner Stop calls=%d want 2", runner.stopCalls.Load())
	}
}

func TestRuntimeManagerTimedOutStopCompletionDoesNotClobberNewStart(t *testing.T) {
	runner := &shutdownBlockingStopRunner{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("stop-generation-guard.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(loaded.Manifest.ID, "old stop"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("old Stop error=%v want deadline", err)
	}
	newStatus, err := m.Start(t.Context(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	close(runner.release)
	select {
	case <-runner.finished:
	case <-time.After(time.Second):
		t.Fatal("old physical Stop did not finish")
	}
	status, ok := m.Status(loaded.Manifest.ID)
	if !ok || status.State != RuntimeStateArmed || status.StartedAt != newStatus.StartedAt {
		t.Fatalf("old stop completion clobbered new generation: ok=%v status=%+v new=%+v", ok, status, newStatus)
	}
}

func TestRuntimeManagerCloseBroadcastsUniqueClosersBeforeWaiting(t *testing.T) {
	one := newShutdownBarrierRunner("one")
	two := newShutdownBarrierRunner("two")
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{
		TypeSystem: one,
		TypeWasm:   one,
		TypeWorker: two,
	}})
	if _, err := m.Start(t.Context(), testRuntimeLoadedOfType("one.bundle", TypeSystem)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(t.Context(), testRuntimeLoadedOfType("two.bundle", TypeWorker)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Close(context.Background()) }()
	for _, entered := range []<-chan struct{}{one.entered, two.entered} {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("Close waited for one closer before broadcasting the next")
		}
	}
	if calls := one.calls.Load(); calls != 1 {
		t.Fatalf("aliased closer calls=%d want 1", calls)
	}
	close(one.release)
	close(two.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeManagerTerminalShutdownStatusSanitizesRunnerError(t *testing.T) {
	runner := &shutdownErrorRunner{err: errors.New("cleanup failed at /private/runtime/token-secret")}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	loaded := testRuntimeLoaded("sanitize-shutdown.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	err := m.Close(t.Context())
	if err == nil || !strings.Contains(err.Error(), "token-secret") {
		t.Fatalf("caller error lost physical cause: %v", err)
	}
	status, _ := m.Status(loaded.Manifest.ID)
	if status.State != RuntimeStateDegraded || status.StoppedAt.IsZero() == false {
		t.Fatalf("terminal cleanup status=%+v", status)
	}
	if strings.Contains(status.Message, "token-secret") || strings.Contains(status.Message, "/private/") || len(status.Message) > 160 {
		t.Fatalf("status exposed raw cleanup detail: %q", status.Message)
	}
}

func TestRuntimeManagerCloseDegradesOnlyAffectedCloserOwners(t *testing.T) {
	bad := &shutdownErrorRunner{err: errors.New("bad closer")}
	good := &shutdownErrorRunner{}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{
		TypeSystem: bad,
		TypeWorker: good,
	}})
	badLoaded := testRuntimeLoadedOfType("bad-close.bundle", TypeSystem)
	goodLoaded := testRuntimeLoadedOfType("good-close.bundle", TypeWorker)
	if _, err := m.Start(t.Context(), badLoaded); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(t.Context(), goodLoaded); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(t.Context()); !errors.Is(err, bad.err) {
		t.Fatalf("Close error=%v want bad closer", err)
	}
	badStatus, _ := m.Status(badLoaded.Manifest.ID)
	goodStatus, _ := m.Status(goodLoaded.Manifest.ID)
	if badStatus.State != RuntimeStateDegraded || !badStatus.StoppedAt.IsZero() {
		t.Fatalf("bad closer status=%+v", badStatus)
	}
	if goodStatus.State != RuntimeStateStopped || goodStatus.StoppedAt.IsZero() {
		t.Fatalf("good closer status=%+v", goodStatus)
	}
}

func TestRuntimeManagerCloseWaitsForStalePreparedCandidateAbort(t *testing.T) {
	runner := newPendingShutdownRunner()
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	loaded := testRuntimeLoaded("pending-abort.bundle")
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	<-runner.prepareEntered
	m.mu.Lock()
	m.runners[TypeSystem] = noopRunner{}
	m.mu.Unlock()
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close(context.Background()) }()
	<-runner.stopAllEntered
	if _, _, err := runner.broker.authority.acquire(context.Background()); !errors.Is(err, errGenerationRevoked) {
		t.Fatalf("pending candidate authority remained live during Close: %v", err)
	}
	status, ok := m.Status(loaded.Manifest.ID)
	if !ok || status.State != RuntimeStateStopping || !status.StoppedAt.IsZero() {
		t.Fatalf("pending candidate status=%+v ok=%v", status, ok)
	}
	close(runner.prepareRelease)
	<-runner.abortEntered
	close(runner.stopAllRelease)
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before stale candidate abort completed: %v", err)
	default:
	}
	close(runner.abortRelease)
	if err := <-startDone; err == nil {
		t.Fatal("stale Start unexpectedly succeeded")
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	status, _ = m.Status(loaded.Manifest.ID)
	if status.State != RuntimeStateStopped || status.StoppedAt.IsZero() {
		t.Fatalf("completed close status=%+v", status)
	}
}

func TestRuntimeManagerStalePendingCleanupOutlivesStopObserver(t *testing.T) {
	runner := newPendingShutdownRunner()
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("stale-cleanup-pending.bundle")
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	<-runner.prepareEntered
	if _, err := m.Stop(loaded.Manifest.ID, "cancel prepare"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Stop error=%v want deadline", err)
	}
	close(runner.prepareRelease)
	<-runner.abortEntered
	if err := <-startDone; err == nil {
		t.Fatal("stale Start unexpectedly succeeded")
	}
	status, err := m.Stop(loaded.Manifest.ID, "observe physical cleanup")
	var shutdownErr *RuntimeShutdownError
	if !errors.As(err, &shutdownErr) || !errors.Is(err, context.DeadlineExceeded) || status.State == RuntimeStateStopped {
		t.Fatalf("pending cleanup status=%+v err=%v typed=%+v", status, err, shutdownErr)
	}
	if !slices.Contains(shutdownErr.PendingStages, "pending-cleanup") {
		t.Fatalf("pending cleanup stages=%v", shutdownErr.PendingStages)
	}
	close(runner.abortRelease)
	status, err = m.Stop(loaded.Manifest.ID, "join physical cleanup")
	if err != nil || status.State != RuntimeStateStopped || status.StoppedAt.IsZero() {
		t.Fatalf("terminal cleanup status=%+v err=%v", status, err)
	}
}

func TestRuntimeManagerPendingCandidateCleanupErrorRemainsDegraded(t *testing.T) {
	runner := newPendingShutdownRunner()
	runner.abortErr = errors.New("candidate abort failed")
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("pending-cleanup-error.bundle")
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	<-runner.prepareEntered
	if _, err := m.Stop(loaded.Manifest.ID, "cancel pending"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop error=%v want deadline", err)
	}
	close(runner.prepareRelease)
	<-runner.abortEntered
	if err := <-startDone; err == nil {
		t.Fatal("pending Start unexpectedly succeeded")
	}
	status, err := m.Stop(loaded.Manifest.ID, "observe failed cleanup")
	var shutdownErr *RuntimeShutdownError
	if !errors.As(err, &shutdownErr) || !slices.Contains(shutdownErr.PendingStages, "pending-cleanup") || status.State == RuntimeStateStopped {
		t.Fatalf("pending failed cleanup status=%+v err=%v typed=%+v", status, err, shutdownErr)
	}
	close(runner.abortRelease)
	status, err = m.Stop(loaded.Manifest.ID, "join pending cleanup")
	if !errors.Is(err, runner.abortErr) || status.State != RuntimeStateDegraded || !status.StoppedAt.IsZero() {
		t.Fatalf("terminal pending cleanup status=%+v err=%v", status, err)
	}
}

func TestRuntimeManagerRetainsUnobservedPendingCleanupErrorUntilStop(t *testing.T) {
	runner := newPendingShutdownRunner()
	runner.abortErr = errors.New("unobserved candidate abort failed")
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	loaded := testRuntimeLoaded("unobserved-cleanup-error.bundle")
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	<-runner.prepareEntered
	m.mu.Lock()
	m.nextGen++
	m.latestGen[loaded.Manifest.ID] = m.nextGen
	pending := m.pendingStarts[loaded.Manifest.ID]
	var cleanup *runtimePendingCleanup
	for _, attempt := range pending {
		cleanup = attempt.cleanup
	}
	m.mu.Unlock()
	close(runner.prepareRelease)
	<-runner.abortEntered
	if err := <-startDone; err == nil {
		t.Fatal("stale Start unexpectedly succeeded")
	}
	close(runner.abortRelease)
	<-cleanup.done
	m.mu.Lock()
	retained := len(m.pendingStarts[loaded.Manifest.ID])
	m.mu.Unlock()
	if retained != 1 {
		t.Fatalf("terminal cleanup error ownership was dropped: retained=%d", retained)
	}
	status, err := m.Stop(loaded.Manifest.ID, "observe retained cleanup error")
	if !errors.Is(err, runner.abortErr) || status.State != RuntimeStateDegraded || !status.StoppedAt.IsZero() {
		t.Fatalf("retained cleanup status=%+v err=%v", status, err)
	}
}

func TestRuntimeManagerActivationFailureCleanupBlocksStop(t *testing.T) {
	runner := newPendingShutdownRunner()
	runner.activateErr = errors.New("activate refused")
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("activation-cleanup.bundle")
	startDone := make(chan error, 1)
	go func() { _, err := m.Start(context.Background(), loaded); startDone <- err }()
	<-runner.prepareEntered
	close(runner.prepareRelease)
	<-runner.abortEntered
	if err := <-startDone; !errors.Is(err, runner.activateErr) {
		t.Fatalf("Start error=%v want activate failure", err)
	}
	status, err := m.Stop(loaded.Manifest.ID, "stop failed activation")
	var shutdownErr *RuntimeShutdownError
	if !errors.As(err, &shutdownErr) || !slices.Contains(shutdownErr.PendingStages, "pending-cleanup") || status.State == RuntimeStateStopped {
		t.Fatalf("activation cleanup status=%+v err=%v typed=%+v", status, err, shutdownErr)
	}
	close(runner.abortRelease)
	status, err = m.Stop(loaded.Manifest.ID, "join failed activation cleanup")
	if err != nil || status.State != RuntimeStateStopped || status.StoppedAt.IsZero() {
		t.Fatalf("activation cleanup terminal status=%+v err=%v", status, err)
	}
}

func TestRuntimeManagerStopDuringCloseCannotPublishStopped(t *testing.T) {
	runner := newShutdownBarrierRunner("close-owner")
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{
		Runners: map[string]Runner{TypeSystem: runner}, StartTimeout: 20 * time.Millisecond,
	})
	loaded := testRuntimeLoaded("stop-during-close.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close(context.Background()) }()
	<-runner.entered
	status, err := m.Stop(loaded.Manifest.ID, "redundant stop")
	var shutdownErr *RuntimeShutdownError
	if !errors.As(err, &shutdownErr) || status.State == RuntimeStateStopped || !status.StoppedAt.IsZero() {
		t.Fatalf("Stop during Close status=%+v err=%v typed=%+v", status, err, shutdownErr)
	}
	if runner.stopCalls.Load() != 0 {
		t.Fatalf("Stop during Close started a second physical path: calls=%d", runner.stopCalls.Load())
	}
	close(runner.release)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeManagerTerminalCloseResultWinsCanceledObserver(t *testing.T) {
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{})
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.Close(ctx); err != nil {
			t.Fatalf("iteration %d terminal Close result lost: %v", i, err)
		}
	}
}

func TestRuntimeManagerCloseStartsRegisteredStopFuture(t *testing.T) {
	runner := &shutdownBlockingStopRunner{
		entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{}),
	}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{})
	const epoch = uint64(7)
	status := RuntimeStatus{PluginID: "registered-stop.bundle", State: RuntimeStateStopping, Message: runtimeStoppingMessage}
	future := &runtimeStopFuture{
		pluginID: status.PluginID, generation: 6, tombstone: epoch, stopGeneration: 6,
		runner: runner, pendingStages: map[string]int{"runner-cleanup": 1}, done: make(chan struct{}), status: status,
	}
	m.nextGen = epoch
	m.latestGen[status.PluginID] = epoch
	m.instances[status.PluginID] = runtimeInstance{generation: epoch, status: status}
	m.stopFutures[status.PluginID] = map[uint64]*runtimeStopFuture{epoch: future}
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close(context.Background()) }()
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("Close did not start the registered stop future")
	}
	close(runner.release)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if runner.calls.Load() != 1 {
		t.Fatalf("registered future runner calls=%d want 1", runner.calls.Load())
	}
}

func TestRuntimeManagerCloseWaitsAuthorityAfterStopAllReturns(t *testing.T) {
	runner := &shutdownErrorRunner{}
	m := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: runner}})
	loaded := testRuntimeLoaded("close-authority.bundle")
	if _, err := m.Start(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	authority := m.instances[loaded.Manifest.ID].broker.authority
	m.mu.Unlock()
	_, release, err := authority.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close(context.Background()) }()
	deadline := time.After(time.Second)
	for {
		_, retryRelease, err := authority.acquire(context.Background())
		if errors.Is(err, errGenerationRevoked) {
			break
		}
		if retryRelease != nil {
			retryRelease()
		}
		select {
		case <-deadline:
			t.Fatal("Close did not revoke live authority")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before authority drained: %v", err)
	default:
	}
	release()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestSystemRunnerTerminalRemoveErrorRemainsDiscoverable(t *testing.T) {
	removeErr := errors.New("remove refused")
	var removeCalls atomic.Int32
	st := shutdownTestState("p.remove", 9, t.TempDir())
	r := &SystemRunner{
		st:        map[string]map[uint64]*systemPluginState{st.pluginID: {st.generation: st}},
		removeAll: func(string) error { removeCalls.Add(1); return removeErr },
	}
	for i := 0; i < 2; i++ {
		err := r.Stop(t.Context(), RunnerStopRequest{PluginID: st.pluginID, Generation: st.generation})
		var cleanupErr *GenerationCleanupError
		if !errors.As(err, &cleanupErr) || !errors.Is(err, removeErr) || cleanupErr.RemoveAll == nil {
			t.Fatalf("Stop %d error=%v typed=%+v", i+1, err, cleanupErr)
		}
	}
	if removeCalls.Load() != 1 {
		t.Fatalf("terminal cleanup repeated remove: calls=%d", removeCalls.Load())
	}
	if r.st[st.pluginID][st.generation] != st {
		t.Fatal("terminally degraded generation was not retained")
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

type shutdownBlockingStopRunner struct {
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
	calls    atomic.Int32
	once     sync.Once
}

func (r *shutdownBlockingStopRunner) Name() string { return "shutdown-blocking-stop" }
func (r *shutdownBlockingStopRunner) Start(context.Context, RunnerStartRequest) (RunnerStartResult, error) {
	if r.finished == nil {
		r.finished = make(chan struct{})
	}
	return RunnerStartResult{Message: "armed"}, nil
}
func (r *shutdownBlockingStopRunner) Stop(context.Context, RunnerStopRequest) error {
	r.calls.Add(1)
	r.once.Do(func() { close(r.entered) })
	<-r.release
	close(r.finished)
	return nil
}

type shutdownBarrierRunner struct {
	name      string
	entered   chan struct{}
	release   chan struct{}
	calls     atomic.Int32
	stopCalls atomic.Int32
	once      sync.Once
}

func newShutdownBarrierRunner(name string) *shutdownBarrierRunner {
	return &shutdownBarrierRunner{name: name, entered: make(chan struct{}), release: make(chan struct{})}
}
func (r *shutdownBarrierRunner) Name() string { return r.name }
func (r *shutdownBarrierRunner) Start(context.Context, RunnerStartRequest) (RunnerStartResult, error) {
	return RunnerStartResult{Message: "armed"}, nil
}
func (r *shutdownBarrierRunner) Stop(context.Context, RunnerStopRequest) error {
	r.stopCalls.Add(1)
	return nil
}
func (r *shutdownBarrierRunner) StopAll(context.Context) error {
	r.calls.Add(1)
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return nil
}

type shutdownErrorRunner struct{ err error }

func (r *shutdownErrorRunner) Name() string { return "shutdown-error" }
func (r *shutdownErrorRunner) Start(context.Context, RunnerStartRequest) (RunnerStartResult, error) {
	return RunnerStartResult{Message: "armed"}, nil
}
func (r *shutdownErrorRunner) Stop(context.Context, RunnerStopRequest) error { return r.err }
func (r *shutdownErrorRunner) StopAll(context.Context) error                 { return r.err }

type stopEpochRunner struct {
	mu                 sync.Mutex
	startCalls         int
	secondStartEntered chan struct{}
	secondStartRelease chan struct{}
	secondBroker       *Broker
	firstStopEntered   chan struct{}
	firstStopRelease   chan struct{}
	stopCalls          atomic.Int32
}

func newStopEpochRunner() *stopEpochRunner {
	return &stopEpochRunner{
		secondStartEntered: make(chan struct{}), secondStartRelease: make(chan struct{}),
		firstStopEntered: make(chan struct{}), firstStopRelease: make(chan struct{}),
	}
}

func (r *stopEpochRunner) Name() string { return "stop-epoch" }
func (r *stopEpochRunner) Start(_ context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	r.mu.Lock()
	r.startCalls++
	call := r.startCalls
	if call == 2 {
		r.secondBroker = req.Broker
	}
	r.mu.Unlock()
	if call == 2 {
		close(r.secondStartEntered)
		<-r.secondStartRelease
	}
	return RunnerStartResult{Message: "armed"}, nil
}
func (r *stopEpochRunner) Stop(context.Context, RunnerStopRequest) error {
	call := r.stopCalls.Add(1)
	if call == 1 {
		close(r.firstStopEntered)
		<-r.firstStopRelease
	}
	return nil
}

type armedPredecessorRunner struct {
	stopCalls         atomic.Int32
	firstStopEntered  chan struct{}
	firstStopRelease  chan struct{}
	secondStopEntered chan struct{}
	secondStopRelease chan struct{}
}

func newArmedPredecessorRunner() *armedPredecessorRunner {
	return &armedPredecessorRunner{
		firstStopEntered: make(chan struct{}), firstStopRelease: make(chan struct{}),
		secondStopEntered: make(chan struct{}), secondStopRelease: make(chan struct{}),
	}
}

func (r *armedPredecessorRunner) Name() string { return "armed-predecessor" }
func (r *armedPredecessorRunner) Start(context.Context, RunnerStartRequest) (RunnerStartResult, error) {
	return RunnerStartResult{Message: "armed"}, nil
}
func (r *armedPredecessorRunner) Stop(context.Context, RunnerStopRequest) error {
	switch r.stopCalls.Add(1) {
	case 1:
		close(r.firstStopEntered)
		<-r.firstStopRelease
	case 2:
		close(r.secondStopEntered)
		<-r.secondStopRelease
	}
	return nil
}

type pendingShutdownRunner struct {
	prepareEntered chan struct{}
	prepareRelease chan struct{}
	abortEntered   chan struct{}
	abortRelease   chan struct{}
	stopAllEntered chan struct{}
	stopAllRelease chan struct{}
	broker         *Broker
	abortErr       error
	activateErr    error
}

func newPendingShutdownRunner() *pendingShutdownRunner {
	return &pendingShutdownRunner{
		prepareEntered: make(chan struct{}), prepareRelease: make(chan struct{}),
		abortEntered: make(chan struct{}), abortRelease: make(chan struct{}),
		stopAllEntered: make(chan struct{}), stopAllRelease: make(chan struct{}),
	}
}

func (r *pendingShutdownRunner) Name() string { return "pending-shutdown" }
func (r *pendingShutdownRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	return r.Prepare(ctx, req)
}

func (r *pendingShutdownRunner) Prepare(_ context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	r.broker = req.Broker
	close(r.prepareEntered)
	<-r.prepareRelease
	return RunnerStartResult{Message: "prepared"}, nil
}
func (r *pendingShutdownRunner) ActivateGeneration(string, uint64) error { return r.activateErr }
func (r *pendingShutdownRunner) AbortGeneration(context.Context, string, uint64) error {
	close(r.abortEntered)
	<-r.abortRelease
	return r.abortErr
}
func (r *pendingShutdownRunner) RetireGeneration(context.Context, string, uint64) error {
	return nil
}
func (r *pendingShutdownRunner) Stop(context.Context, RunnerStopRequest) error { return nil }
func (r *pendingShutdownRunner) StopAll(context.Context) error {
	close(r.stopAllEntered)
	<-r.stopAllRelease
	return nil
}

func testRuntimeLoadedOfType(id, typ string) Loaded {
	return Loaded{
		Manifest:     Manifest{ID: id, Name: id, Type: typ, Capabilities: []string{"kv:read"}},
		Capabilities: []string{"kv:read"},
	}
}
