package plugin

import (
	"context"
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
	wantPGIDs := []int{idle.pgid}
	slices.Sort(wantPGIDs)
	if snapshot.Generation != 1 || snapshot.Err == nil || !slices.Equal(snapshot.ResidualPGIDs, wantPGIDs) || !slices.Contains(snapshot.PendingStages, "joins") || !slices.Contains(snapshot.PendingStages, "leases") {
		t.Fatalf("pending snapshot=%+v want pgids=%v", snapshot, wantPGIDs)
	}
	snapshot.ResidualPGIDs[0] = -1
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
			entry := p.drainFuture.entries[tr]
			p.mu.Unlock()
			if entry == nil || !entry.terminal {
				t.Fatalf("retirement was not terminal in shared ledger: %#v", entry)
			}
			if result := p.beginDrain(true, 1).wait(t.Context()); result.Err != nil {
				t.Fatalf("drain result=%+v", result)
			}
		})
	}
}
