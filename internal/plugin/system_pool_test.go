package plugin

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSystemPoolGenerationAndExclusiveLease(t *testing.T) {
	p := newSystemPool(2, time.Hour)
	if err := p.publish(1, false, time.Now()); err == nil {
		t.Fatal("unready worker published")
	}
	if err := p.publish(1, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	w, err := p.checkout(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := p.checkout(ctx, time.Now()); err == nil {
		t.Fatal("second checkout exceeded pool bound")
	}
	p.release(w, true, time.Now())
	if _, err := p.checkout(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	p.drain(1)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	if _, err := p.checkout(ctx2, time.Now()); err == nil {
		t.Fatal("drained pool leased worker")
	}
}

func TestSystemPoolConcurrentNoDoubleLease(t *testing.T) {
	p := newSystemPool(1, time.Hour)
	_ = p.publish(1, true, time.Now())
	var wg sync.WaitGroup
	var mu sync.Mutex
	leases := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			w, err := p.checkout(ctx, time.Now())
			if err == nil {
				mu.Lock()
				leases++
				mu.Unlock()
				time.Sleep(time.Millisecond)
				p.release(w, false, time.Now())
			}
		}()
	}
	wg.Wait()
	if leases != 1 {
		t.Fatalf("leases=%d, expected one concurrent lease", leases)
	}
}

func TestSystemPoolPrimaryOverflowCapacity(t *testing.T) {
	p := newSystemPool(2, time.Hour)
	if err := p.publish(1, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := p.publish(1, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := p.publish(1, true, time.Now()); err == nil {
		t.Fatal("pool exceeded primary+overflow capacity")
	}
}

func TestSystemPoolGracefulDrainRetiresLeasedWithoutResurrection(t *testing.T) {
	p := newSystemPool(2, time.Hour)
	if err := p.publish(1, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	w, err := p.checkout(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.gracefulDrain(1)
	p.mu.Lock()
	if !p.closed || p.active != 1 || len(p.leased) != 1 {
		t.Fatalf("closed=%v active=%d leased=%d", p.closed, p.active, len(p.leased))
	}
	p.mu.Unlock()
	p.release(w, true, time.Now())
	select {
	case <-p.drained:
	case <-time.After(time.Second):
		t.Fatal("drain did not complete")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != 0 || len(p.leased) != 0 || len(p.workers) != 0 {
		t.Fatalf("resurrected pool: active=%d leased=%d workers=%d", p.active, len(p.leased), len(p.workers))
	}
}

func TestSystemPoolActiveMatchesLeasedAcrossTransitions(t *testing.T) {
	p := newSystemPool(2, time.Hour)
	if err := p.publish(1, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	w, err := p.checkout(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	if !p.invariantLocked() {
		t.Fatal("checkout invariant")
	}
	p.mu.Unlock()
	p.release(w, false, time.Now())
	p.mu.Lock()
	if !p.invariantLocked() {
		t.Fatal("release invariant")
	}
	p.mu.Unlock()
	w, err = p.checkout(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.poison(w)
	p.mu.Lock()
	if !p.invariantLocked() {
		t.Fatal("poison invariant")
	}
	p.mu.Unlock()
}

func TestSystemPoolOverflowReservesSingleStartingWorker(t *testing.T) {
	p := newSystemPool(2, time.Hour)
	_ = p.publish(1, true, time.Now())
	w, err := p.checkout(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	var calls atomic.Int64
	p.replenishFn = func(ctx context.Context, _ uint64) (*pooledWorker, error) {
		calls.Add(1)
		select {
		case <-gate:
			return &pooledWorker{generation: 1, started: time.Now()}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan *pooledWorker, 1)
	go func() { x, _ := p.checkout(ctx, time.Now()); done <- x }()
	time.Sleep(time.Millisecond)
	p.mu.Lock()
	if p.starting != 1 {
		t.Fatalf("starting=%d", p.starting)
	}
	p.mu.Unlock()
	close(gate)
	select {
	case x := <-done:
		if x == nil {
			t.Fatal("no overflow lease")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	p.release(w, false, time.Now())
	if calls.Load() != 1 {
		t.Fatalf("spawn calls=%d", calls.Load())
	}
}

func TestSystemPoolWaiterReceivesCloseError(t *testing.T) {
	p := newSystemPool(2, time.Hour)
	entered := make(chan struct{})
	p.replenishFn = func(ctx context.Context, _ uint64) (*pooledWorker, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.checkout(ctx, time.Now()); done <- err }()
	<-entered
	p.abortClose(1)
	select {
	case err := <-done:
		if err != errSystemPoolClosed {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter not woken")
	}
}

func TestSystemPoolReplenishFailuresOpenCircuitAndStopAttempts(t *testing.T) {
	p := newSystemPool(8, time.Hour, 11)
	p.jitterFn = func(delay time.Duration) time.Duration { return delay }
	p.waitBackoff = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	var mu sync.Mutex
	attempts := 0
	attempted := make(chan int, 4)
	p.replenishFn = func(context.Context, uint64) (*pooledWorker, error) {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		attempted <- attempt
		return nil, errors.New("spawn failed")
	}
	p.failureFn = func(uint64) {
		mu.Lock()
		count := attempts
		mu.Unlock()
		if count >= 3 {
			p.setCircuitOpen(true)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.checkout(ctx, time.Now()); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("checkout error=%v want ErrCircuitOpen", err)
	}
	for want := 1; want <= 3; want++ {
		select {
		case got := <-attempted:
			if got != want {
				t.Fatalf("attempt=%d want %d", got, want)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	mu.Lock()
	got := attempts
	mu.Unlock()
	if got != 3 {
		t.Fatalf("replenish attempts=%d want exactly 3", got)
	}
	p.abortClose(11)
}

func TestSystemPoolSuccessfulReplenishmentResetsConsecutiveFailures(t *testing.T) {
	p := newSystemPool(8, time.Hour, 13)
	p.jitterFn = func(delay time.Duration) time.Duration { return delay }
	p.waitBackoff = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	var mu sync.Mutex
	consecutive := 0
	attempts := 0
	p.failureFn = func(uint64) {
		mu.Lock()
		defer mu.Unlock()
		consecutive++
		if consecutive >= 3 {
			p.setCircuitOpen(true)
		}
	}
	p.successFn = func(uint64) {
		mu.Lock()
		consecutive = 0
		mu.Unlock()
	}
	p.replenishFn = func(context.Context, uint64) (*pooledWorker, error) {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		if attempt == 3 {
			return &pooledWorker{started: time.Now()}, nil
		}
		return nil, errors.New("spawn failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := p.checkout(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.poison(w)
	if _, err := p.checkout(ctx, time.Now()); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("checkout error=%v want ErrCircuitOpen", err)
	}
	mu.Lock()
	gotAttempts, gotConsecutive := attempts, consecutive
	mu.Unlock()
	if gotAttempts != 6 || gotConsecutive != 3 {
		t.Fatalf("attempts=%d consecutive=%d want 6/3", gotAttempts, gotConsecutive)
	}
	p.abortClose(13)
}

func TestSystemPoolCanceledAttemptDoesNotKillSupervisor(t *testing.T) {
	p := newSystemPool(8, time.Hour, 12)
	p.backoffBase = time.Millisecond
	var attempts atomic.Int32
	p.replenishFn = func(ctx context.Context, generation uint64) (*pooledWorker, error) {
		if attempts.Add(1) == 1 {
			return nil, context.Canceled
		}
		return &pooledWorker{generation: generation, started: time.Now()}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := p.checkout(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts=%d want 2", attempts.Load())
	}
	p.release(w, true, time.Now())
	p.abortClose(12)
}
