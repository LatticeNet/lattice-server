package plugin

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recordingPoolObserver counts every observation under its own lock, exactly
// as a real telemetry sink would.
type recordingPoolObserver struct {
	mu        sync.Mutex
	durations map[SystemPoolDurationPhase]int
	lifecycle map[SystemPoolLifecycleEvent]int
	circuit   map[SystemPoolCircuitTransition]int
	retire    map[SystemPoolRetirementReason]int
}

func newRecordingPoolObserver() *recordingPoolObserver {
	return &recordingPoolObserver{
		durations: map[SystemPoolDurationPhase]int{},
		lifecycle: map[SystemPoolLifecycleEvent]int{},
		circuit:   map[SystemPoolCircuitTransition]int{},
		retire:    map[SystemPoolRetirementReason]int{},
	}
}

func (o *recordingPoolObserver) ObserveSystemPoolDuration(phase SystemPoolDurationPhase, d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.durations[phase]++
}

func (o *recordingPoolObserver) ObserveSystemPoolLifecycle(event SystemPoolLifecycleEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lifecycle[event]++
}

func (o *recordingPoolObserver) ObserveSystemPoolCircuit(transition SystemPoolCircuitTransition) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.circuit[transition]++
}

func (o *recordingPoolObserver) ObserveSystemPoolRetirement(reason SystemPoolRetirementReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.retire[reason]++
}

func (o *recordingPoolObserver) retirementCount(reason SystemPoolRetirementReason) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.retire[reason]
}

func (o *recordingPoolObserver) lifecycleCount(event SystemPoolLifecycleEvent) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lifecycle[event]
}

func (o *recordingPoolObserver) circuitCount(transition SystemPoolCircuitTransition) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.circuit[transition]
}

func (o *recordingPoolObserver) durationCount(phase SystemPoolDurationPhase) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.durations[phase]
}

// Lease-end retirements must name the exact rule that ended the worker, in
// the same priority order the pool evaluates.
func TestSystemPoolObserverAttributesLeaseEndRetirements(t *testing.T) {
	t.Run("max uses", func(t *testing.T) {
		obs := newRecordingPoolObserver()
		p := newSystemPool(1, time.Hour, 7)
		p.obs = obs
		if err := p.publish(7, true, time.Now()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		w, err := p.checkout(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p.finishLease(w, true, true, time.Now())
		if got := obs.retirementCount(SystemPoolRetirementMaxUses); got != 1 {
			t.Fatalf("max-uses retirements=%d, want 1 (all=%v)", got, obs.retire)
		}
	})

	t.Run("max age", func(t *testing.T) {
		obs := newRecordingPoolObserver()
		p := newSystemPool(256, time.Minute, 7)
		p.obs = obs
		if err := p.publish(7, true, time.Now()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		w, err := p.checkout(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// The lease ends at a time past the age ceiling; the clock is an input
		// here, so the ceiling is crossed without waiting for it.
		p.finishLease(w, true, true, time.Now().Add(2*time.Minute))
		if got := obs.retirementCount(SystemPoolRetirementMaxAge); got != 1 {
			t.Fatalf("max-age retirements=%d, want 1 (all=%v)", got, obs.retire)
		}
	})

	t.Run("circuit open", func(t *testing.T) {
		obs := newRecordingPoolObserver()
		p := newSystemPool(256, time.Hour, 7)
		p.obs = obs
		if err := p.publish(7, true, time.Now()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		w, err := p.checkout(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		p.circuitOpen = true
		p.mu.Unlock()
		p.finishLease(w, true, true, time.Now())
		if got := obs.retirementCount(SystemPoolRetirementCircuitOpen); got != 1 {
			t.Fatalf("circuit-open retirements=%d, want 1 (all=%v)", got, obs.retire)
		}
	})

	t.Run("stale generation is rejected", func(t *testing.T) {
		obs := newRecordingPoolObserver()
		p := newSystemPool(256, time.Hour, 7)
		p.obs = obs
		w := &pooledWorker{generation: 6, started: time.Now()}
		p.mu.Lock()
		p.leased[w] = struct{}{}
		p.active++
		p.mu.Unlock()
		p.finishLease(w, true, true, time.Now())
		if got := obs.retirementCount(SystemPoolRetirementRejected); got != 1 {
			t.Fatalf("rejected retirements=%d, want 1 (all=%v)", got, obs.retire)
		}
	})

	t.Run("poison", func(t *testing.T) {
		obs := newRecordingPoolObserver()
		p := newSystemPool(256, time.Hour, 7)
		p.obs = obs
		if err := p.publish(7, true, time.Now()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		w, err := p.checkout(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p.poison(w)
		if got := obs.retirementCount(SystemPoolRetirementPoisoned); got != 1 {
			t.Fatalf("poisoned retirements=%d, want 1 (all=%v)", got, obs.retire)
		}
	})
}

// Opening the circuit is one transition however many times it is asserted,
// and every idle worker dropped by it is attributed to the circuit — while a
// drain attributes its drops to shutdown.
func TestSystemPoolObserverCountsCircuitAndDrain(t *testing.T) {
	obs := newRecordingPoolObserver()
	p := newSystemPool(256, time.Hour, 7)
	p.obs = obs
	if err := p.publish(7, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := p.publish(7, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	p.setCircuitOpen(true)
	p.setCircuitOpen(true)
	if got := obs.circuitCount(SystemPoolCircuitOpened); got != 1 {
		t.Fatalf("circuit opened transitions=%d, want 1", got)
	}
	if got := obs.retirementCount(SystemPoolRetirementCircuitOpen); got != 2 {
		t.Fatalf("circuit-open retirements=%d, want 2 (all=%v)", got, obs.retire)
	}

	// wakeLocked's circuit branch drops idle workers that surface while the
	// circuit is already open; each drop is a circuit retirement too.
	obsWake := newRecordingPoolObserver()
	wakePool := newSystemPool(256, time.Hour, 7)
	wakePool.obs = obsWake
	if err := wakePool.publish(7, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	wakePool.mu.Lock()
	wakePool.circuitOpen = true
	retiredByWake := wakePool.wakeLocked(time.Now())
	wakePool.mu.Unlock()
	_ = retiredByWake
	if got := obsWake.retirementCount(SystemPoolRetirementCircuitOpen); got != 1 {
		t.Fatalf("wakeLocked circuit retirements=%d, want 1 (all=%v)", got, obsWake.retire)
	}

	obs2 := newRecordingPoolObserver()
	drainPool := newSystemPool(256, time.Hour, 7)
	drainPool.obs = obs2
	if err := drainPool.publish(7, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	drainPool.drain(7)
	if got := obs2.retirementCount(SystemPoolRetirementShutdown); got != 1 {
		t.Fatalf("shutdown retirements=%d, want 1 (all=%v)", got, obs2.retire)
	}
}

// Supervisor start attempts are observed as durations plus a success or a
// failure; a canceled shutdown attempt is neither.
func TestSystemPoolObserverCountsSupervisorStarts(t *testing.T) {
	obs := newRecordingPoolObserver()
	p := newSystemPool(2, time.Hour)
	p.obs = obs
	p.backoffBase = time.Millisecond
	if err := p.publish(1, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	firstCtx, firstCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer firstCancel()
	w, err := p.checkout(firstCtx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var failedOnce bool
	var failMu sync.Mutex
	p.replenishFn = func(ctx context.Context, _ uint64) (*pooledWorker, error) {
		failMu.Lock()
		defer failMu.Unlock()
		if !failedOnce {
			failedOnce = true
			return nil, errors.New("spawn refused")
		}
		return &pooledWorker{generation: 1, started: time.Now()}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	overflow, err := p.checkout(ctx, time.Now())
	if err != nil {
		t.Fatalf("overflow checkout: %v", err)
	}
	if got := obs.lifecycleCount(SystemPoolLifecycleWorkerStartFailure); got != 1 {
		t.Fatalf("start failures=%d, want 1", got)
	}
	if got := obs.lifecycleCount(SystemPoolLifecycleWorkerStartSuccess); got != 1 {
		t.Fatalf("start successes=%d, want 1", got)
	}
	if got := obs.durationCount(SystemPoolDurationStart); got != 2 {
		t.Fatalf("start durations=%d, want 2", got)
	}
	p.release(overflow, false, time.Now())
	p.release(w, false, time.Now())
	p.drain(1)
}

// A real pooled invocation is measured end to end: queue, handler, and total
// each exactly once, and the worker's fate is counted where it is decided.
func TestSystemRunnerObserverSeesWarmInvocationTruth(t *testing.T) {
	obs := newRecordingPoolObserver()
	worker := startReadyTestWorker(t)
	pool := newSystemPool(256, time.Hour, 1)
	pool.obs = obs
	if err := pool.publishTransport(1, worker, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.drain(1) })
	runner := runnerWithPool(pool, nil)
	runner.opts.PoolObserver = obs

	first, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "first"})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if !first.OK {
		t.Fatalf("response=%+v", first)
	}
	for _, phase := range []SystemPoolDurationPhase{SystemPoolDurationQueue, SystemPoolDurationHandler, SystemPoolDurationTotal} {
		if got := obs.durationCount(phase); got != 1 {
			t.Fatalf("duration phase %d observed %d times, want 1 (all=%v)", phase, got, obs.durations)
		}
	}
	if got := obs.lifecycleCount(SystemPoolLifecycleInvocationReusable); got != 1 {
		t.Fatalf("reusable invocations=%d, want 1", got)
	}
	if got := obs.lifecycleCount(SystemPoolLifecycleInvocationFailure); got != 0 {
		t.Fatalf("failure invocations=%d, want 0", got)
	}
}

// An invocation whose worker retires after its result is a counted failure
// and a poisoned retirement — while the caller still gets the result.
func TestSystemRunnerObserverCountsPoisonedInvocation(t *testing.T) {
	obs := newRecordingPoolObserver()
	worker := startReadyTestWorker(t, "LATTICE_TEST_V2_NO_READY_AFTER_RESULT=1")
	pool := newSystemPool(256, time.Hour, 1)
	pool.obs = obs
	if err := pool.publishTransport(1, worker, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.drain(1) })
	runner := runnerWithPool(pool, nil)
	runner.opts.PoolObserver = obs

	response, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "first"})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if !response.OK {
		t.Fatalf("response=%+v", response)
	}
	if got := obs.lifecycleCount(SystemPoolLifecycleInvocationFailure); got != 1 {
		t.Fatalf("failure invocations=%d, want 1", got)
	}
	if got := obs.retirementCount(SystemPoolRetirementPoisoned); got != 1 {
		t.Fatalf("poisoned retirements=%d, want 1 (all=%v)", got, obs.retire)
	}
	if got := obs.lifecycleCount(SystemPoolLifecycleInvocationReusable); got != 0 {
		t.Fatalf("reusable invocations=%d, want 0", got)
	}
}
