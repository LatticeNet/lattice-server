package plugin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
)

func TestSystemPoolForceDrainBroadcastsBeforeJoining(t *testing.T) {
	p := newSystemPool(256, time.Hour, 1)
	p.maxOverflow = 2
	entered := make(chan int, 3)
	release := make(chan struct{})
	for i := 0; i < 3; i++ {
		tr := startReadyTestWorker(t)
		index := i
		tr.beforeAbortFinish = func() { entered <- index; <-release }
		if err := p.publishTransport(1, tr, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	future := p.beginDrain(true, 1)
	seen := make(map[int]bool)
	for len(seen) < 3 {
		select {
		case index := <-entered:
			seen[index] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d abort requests reached owned finishers", len(seen))
		}
	}
	select {
	case <-future.done:
		t.Fatal("drain finalized while joins were blocked")
	default:
	}
	close(release)
	if result := future.wait(t.Context()); result.Err != nil {
		t.Fatalf("drain result=%+v", result)
	}
}

func TestSystemPoolGracefulDrainRegistersReleasedLease(t *testing.T) {
	p := newSystemPool(256, time.Hour, 1)
	tr := startReadyTestWorker(t)
	entered := make(chan struct{})
	releaseJoin := make(chan struct{})
	tr.beforeAbortFinish = func() { close(entered); <-releaseJoin }
	if err := p.publishTransport(1, tr, time.Now()); err != nil {
		t.Fatal(err)
	}
	worker, err := p.checkout(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	future := p.beginDrain(false, 1)
	select {
	case <-entered:
		t.Fatal("graceful drain aborted a leased worker")
	default:
	}
	released := make(chan struct{})
	go func() { p.release(worker, true, time.Now()); close(released) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("released lease was not registered and requested")
	}
	select {
	case <-future.done:
		t.Fatal("future closed before released transport joined")
	default:
	}
	close(releaseJoin)
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("release did not preserve caller-visible join semantics")
	}
	if result := future.wait(t.Context()); result.Err != nil {
		t.Fatalf("drain result=%+v", result)
	}
}

func TestSystemPoolForceUpgradeReusesFutureAndOwnsRacingRelease(t *testing.T) {
	for iteration := 0; iteration < 25; iteration++ {
		p := newSystemPool(256, time.Hour, 1)
		tr := startReadyTestWorker(t)
		entered := make(chan struct{})
		releaseJoin := make(chan struct{})
		tr.beforeAbortFinish = func() { close(entered); <-releaseJoin }
		if err := p.publishTransport(1, tr, time.Now()); err != nil {
			t.Fatal(err)
		}
		worker, err := p.checkout(t.Context(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		graceful := p.beginDrain(false, 1)
		forceResult := make(chan *poolDrainFuture, 1)
		releaseDone := make(chan struct{})
		go func() { forceResult <- p.beginDrain(true, 1) }()
		go func() { p.release(worker, true, time.Now()); close(releaseDone) }()
		force := <-forceResult
		if force != graceful {
			t.Fatal("force upgrade returned a different future")
		}
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("force upgrade did not abort remaining lease")
		}
		p.mu.Lock()
		if !p.invariantLocked() || p.active != 0 || len(p.leased) != 0 || len(p.drainFuture.entries) != 1 {
			t.Fatalf("iteration %d invariant active=%d leased=%d entries=%d", iteration, p.active, len(p.leased), len(p.drainFuture.entries))
		}
		p.mu.Unlock()
		close(releaseJoin)
		select {
		case <-releaseDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d release did not finish after join", iteration)
		}
		if result := graceful.wait(t.Context()); result.Err != nil {
			t.Fatalf("iteration %d drain result=%+v", iteration, result)
		}
	}
}

func TestPoolDrainFutureWaitReportsStablePendingSnapshot(t *testing.T) {
	p := newSystemPool(256, time.Hour, 1)
	p.maxOverflow = 1
	idle := startReadyTestWorker(t)
	leasedTransport := startReadyTestWorker(t)
	idleRelease := make(chan struct{})
	leasedRelease := make(chan struct{})
	idle.beforeAbortFinish = func() { <-idleRelease }
	leasedTransport.beforeAbortFinish = func() { <-leasedRelease }
	if err := p.publishTransport(1, leasedTransport, time.Now()); err != nil {
		t.Fatal(err)
	}
	leased, err := p.checkout(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.publishTransport(1, idle, time.Now()); err != nil {
		t.Fatal(err)
	}
	future := p.beginDrain(false, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot := future.wait(ctx)
	if snapshot.Generation != 1 || snapshot.Err == nil || !slices.Contains(snapshot.PendingStages, "joins") || !slices.Contains(snapshot.PendingStages, "leases") {
		t.Fatalf("pending snapshot=%+v", snapshot)
	}
	wantPGIDs := append([]int(nil), snapshot.ResidualPGIDs...)
	if len(snapshot.ResidualPGIDs) > 0 {
		snapshot.ResidualPGIDs[0] = -1
	}
	again := future.wait(ctx)
	if !slices.Equal(again.ResidualPGIDs, wantPGIDs) {
		t.Fatalf("snapshot was not deep/stable: %+v", again)
	}
	close(idleRelease)
	released := make(chan struct{})
	go func() { p.release(leased, true, time.Now()); close(released) }()
	close(leasedRelease)
	<-released
	if result := future.wait(t.Context()); result.Err != nil || result.Stage != "complete" {
		t.Fatalf("final result=%+v", result)
	}
}

func TestSystemPoolRetirementPathsRegisterWithDrainLedger(t *testing.T) {
	cases := []struct {
		name string
		act  func(*systemPool, *pooledWorker)
	}{
		{name: "poison", act: func(p *systemPool, w *pooledWorker) { p.poison(w) }},
		{name: "circuit", act: func(p *systemPool, _ *pooledWorker) { p.setCircuitOpen(true) }},
		{name: "max-use", act: func(p *systemPool, _ *pooledWorker) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = p.checkout(ctx, time.Now())
		}},
		{name: "max-age", act: func(p *systemPool, _ *pooledWorker) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = p.checkout(ctx, time.Now().Add(2*time.Hour))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSystemPool(1, time.Hour, 1)
			tr := startReadyTestWorker(t)
			worker := &pooledWorker{state: workerIdle, generation: 1, started: time.Now(), transport: tr}
			if tc.name == "poison" {
				p.workers = append(p.workers, worker)
				leased, err := p.checkout(t.Context(), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				worker = leased
			} else {
				if tc.name == "max-use" {
					worker.uses = 1
				}
				p.workers = append(p.workers, worker)
			}
			tc.act(p, worker)
			p.mu.Lock()
			entry := p.drainFuture.ordered[len(p.drainFuture.ordered)-1]
			activeEntries := len(p.drainFuture.entries)
			p.mu.Unlock()
			if entry == nil || !entry.terminal || entry.transport != nil || entry.pgid != tr.pgid || activeEntries != 0 {
				t.Fatalf("retirement was not compacted in shared ledger: entry=%#v active=%d", entry, activeEntries)
			}
			if result := p.beginDrain(true, 1).wait(t.Context()); result.Err != nil {
				t.Fatalf("drain result=%+v", result)
			}
		})
	}
}

func TestSystemPoolFailedReadinessCandidateCleanupReachesLedger(t *testing.T) {
	p := newSystemPool(8, time.Hour, 1)
	injected := errors.New("injected readiness cleanup failure")
	entered := make(chan struct{})
	release := make(chan struct{})
	pgid := make(chan int, 1)
	p.replenishFn = func(context.Context, uint64) (*pooledWorker, error) {
		env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_IGNORE_TERM=1")
		tr, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
		if err != nil {
			return nil, err
		}
		pgid <- tr.pgid
		tr.beforeAbortFinish = func() { close(entered); <-release }
		tr.reapProcessGroupFn = func() error {
			_ = tr.reapProcessGroup()
			return injected
		}
		return readyPooledWorker(t.Context(), 2, tr)
	}
	p.failureFn = func(uint64) { p.setCircuitOpen(true) }
	checkout := make(chan error, 1)
	go func() {
		_, err := p.checkout(t.Context(), time.Now())
		checkout <- err
	}()
	candidatePGID := <-pgid
	<-entered
	select {
	case err := <-checkout:
		if !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("checkout error=%v want ErrCircuitOpen before teardown release", err)
		}
	case <-time.After(time.Second):
		t.Fatal("circuit failure was not published before teardown join")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	future := p.beginDrain(true, 1)
	snapshot := future.wait(ctx)
	if !slices.Contains(snapshot.ResidualPGIDs, candidatePGID) || !slices.Contains(snapshot.PendingStages, "joins") || !slices.Contains(snapshot.PendingStages, "supervisor") {
		t.Fatalf("pending cleanup snapshot=%+v want candidate pgid=%d and join/supervisor stages", snapshot, candidatePGID)
	}
	close(release)
	result := future.wait(t.Context())
	if !errors.Is(result.Err, injected) || len(result.ResidualPGIDs) != 0 {
		t.Fatalf("cleanup result=%+v want injected error without residual process", result)
	}
	assertProcessGroupGone(t, candidatePGID)
}

func TestSystemPoolLateRejectedPublishOwnsCleanupAfterFinalization(t *testing.T) {
	p := newSystemPool(8, time.Hour, 1)
	if result := p.beginDrain(true, 1).wait(t.Context()); result.Err != nil {
		t.Fatalf("empty drain=%+v", result)
	}
	tr := startReadyTestWorker(t)
	injected := errors.New("injected late-candidate cleanup failure")
	entered := make(chan struct{})
	release := make(chan struct{})
	tr.beforeAbortFinish = func() { close(entered); <-release }
	tr.reapProcessGroupFn = func() error {
		_ = tr.reapProcessGroup()
		return injected
	}
	published := make(chan error, 1)
	go func() { published <- p.publishTransport(1, tr, time.Now()) }()
	<-entered
	select {
	case err := <-published:
		t.Fatalf("rejected publish returned before owned cleanup joined: %v", err)
	default:
	}
	close(release)
	if err := <-published; !errors.Is(err, injected) {
		t.Fatalf("rejected publish lost cleanup error: %v", err)
	}
}

func TestSystemPoolTerminalRetirementsCompactTransportReferences(t *testing.T) {
	p := newSystemPool(1, time.Hour, 1)
	const churn = 32
	for i := 0; i < churn; i++ {
		tr := startReadyTestWorker(t)
		if err := p.publishTransport(1, tr, time.Now()); err != nil {
			t.Fatal(err)
		}
		worker, err := p.checkout(t.Context(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p.poison(worker)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.drainFuture.entries) != 0 || len(p.drainFuture.ordered) != churn {
		t.Fatalf("active entries=%d summaries=%d want 0/%d", len(p.drainFuture.entries), len(p.drainFuture.ordered), churn)
	}
	for i, entry := range p.drainFuture.ordered {
		if !entry.terminal || entry.transport != nil || entry.pgid == 0 {
			t.Fatalf("summary %d retained terminal transport: %#v", i, entry)
		}
	}
}

func TestPoolCleanupResidualPGIDsRequirePositiveLiveness(t *testing.T) {
	for _, stage := range []string{"pipe-close", "stdout-join", "stderr-join", "leader-wait"} {
		t.Run(stage, func(t *testing.T) {
			p := newSystemPool(8, time.Hour, 1)
			injected := errors.New("injected " + stage + " failure")
			flags := []string(nil)
			if stage == "leader-wait" {
				flags = append(flags, "LATTICE_TEST_V2_EXIT_AFTER_READY_CODE=7")
			}
			tr := startReadyTestWorker(t, flags...)
			switch stage {
			case "pipe-close":
				tr.closePipesFn = func() error { return injected }
			case "stdout-join":
				tr.waitMu.Lock()
				tr.readPumpErr = injected
				tr.waitMu.Unlock()
			case "stderr-join":
				tr.waitMu.Lock()
				tr.stderrPumpErr = injected
				tr.waitMu.Unlock()
			case "leader-wait":
				<-tr.waitDone
			}
			if err := p.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			worker, err := p.checkout(t.Context(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			p.poison(worker)
			result := p.beginDrain(true, 1).wait(t.Context())
			var affected *processGroupResidualError
			if len(result.ResidualPGIDs) != 0 || !errors.As(result.Err, &affected) || affected.Stage != stage {
				t.Fatalf("result=%+v affected=%#v", result, affected)
			}
			if stage == "leader-wait" {
				var exitErr *exec.ExitError
				if !errors.As(result.Err, &exitErr) || exitErr.ExitCode() != 7 {
					t.Fatalf("leader wait error=%v want exit 7", result.Err)
				}
			} else if !errors.Is(result.Err, injected) {
				t.Fatalf("result=%+v want injected %s error", result, stage)
			}
			assertProcessGroupGone(t, tr.pgid)
		})
	}
}
