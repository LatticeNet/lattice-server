package plugin

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

type systemWorkerState uint8

const (
	workerStarting systemWorkerState = iota
	workerIdle
	workerLeased
	workerResultSeen
	workerResetting
	workerRetiring
	workerDead
)

type pooledWorker struct {
	state      systemWorkerState
	generation uint64
	uses       int
	started    time.Time
	transport  *systemWorkerTransport
}

// systemPool provides generation-fenced FIFO leases. Process transport is
// deliberately supplied by the runner; this type owns lifecycle invariants.
type systemPool struct {
	mu          sync.Mutex
	generation  uint64
	workers     []*pooledWorker
	waiters     []chan poolCheckoutResult
	maxUses     int
	maxAge      time.Duration
	size        int
	maxOverflow int
	activated   bool
	closed      bool
	replenishFn func(context.Context, uint64) (*pooledWorker, error)
	failureFn   func(uint64)
	successFn   func(uint64)
	active      int
	starting    int
	drained     chan struct{}
	leased      map[*pooledWorker]struct{}
	circuitOpen bool
	superCtx    context.Context
	superCancel context.CancelFunc
	superSignal chan struct{}
	superDone   chan struct{}
	superStart  bool
	attemptStop context.CancelFunc
	backoffBase time.Duration
	jitterFn    func(time.Duration) time.Duration
	waitBackoff func(context.Context, time.Duration) bool
	drainFuture *poolDrainFuture
	// Test-only ownership boundary hook for cancellation-vs-wake reconciliation.
	beforeCancelReconcile func()
	// Test-only result-arm hook for cancellation after assignment but before the
	// lease is returned to a caller for dispatch.
	beforeResultReturn func()
}

type poolCheckoutResult struct {
	worker *pooledWorker
	err    error
}

var errSystemPoolClosed = errors.New("system pool closed")

// PoolCleanupResult is the owned, generation-scoped teardown ledger.  A
// future is returned so callers can broadcast abort requests first and join
// all transports under their own deadline.
type PoolCleanupResult struct {
	Generation    uint64
	Err           error
	ResidualPGIDs []int
	Stage         string
	PendingStages []string
}

type poolDrainFuture struct {
	pool              *systemPool
	done              chan struct{}
	generation        uint64
	started           bool
	force             bool
	supervisorPending bool
	leasedPending     int
	entries           map[*systemWorkerTransport]*poolDrainEntry
	ordered           []*poolDrainEntry
	nextSequence      uint64
	finalized         bool
	result            PoolCleanupResult
}

type poolDrainEntry struct {
	sequence  uint64
	transport *systemWorkerTransport
	pgid      int
	done      chan struct{}
	joinOnce  sync.Once
	terminal  bool
	residual  bool
	err       error
}

func (f *poolDrainFuture) wait(ctx context.Context) PoolCleanupResult {
	if f == nil {
		return PoolCleanupResult{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-f.done:
		return f.snapshot(nil)
	case <-ctx.Done():
		return f.snapshot(ctx.Err())
	}
}

func (f *poolDrainFuture) snapshot(waitErr error) PoolCleanupResult {
	p := f.pool
	if p == nil {
		return clonePoolCleanupResult(f.result)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.finalized {
		return clonePoolCleanupResult(f.result)
	}
	r := PoolCleanupResult{Generation: f.generation, Stage: "pool-drain-pending"}
	var joined error
	if waitErr != nil {
		joined = waitErr
	}
	if f.supervisorPending {
		r.PendingStages = append(r.PendingStages, "supervisor")
	}
	if f.leasedPending > 0 {
		r.PendingStages = append(r.PendingStages, "leases")
	}
	for _, entry := range f.ordered {
		if entry.terminal {
			joined = errors.Join(joined, entry.err)
			if entry.residual && entry.pgid != 0 {
				r.ResidualPGIDs = append(r.ResidualPGIDs, entry.pgid)
			}
			continue
		}
		r.PendingStages = append(r.PendingStages, "joins")
		if entry.pgid != 0 {
			if processGroupExists(entry.pgid) {
				r.ResidualPGIDs = append(r.ResidualPGIDs, entry.pgid)
			}
			if waitErr != nil {
				joined = errors.Join(joined, &processGroupResidualError{PGID: entry.pgid, Stage: "pool-join-pending", Err: waitErr})
			}
		}
	}
	slices.Sort(r.ResidualPGIDs)
	r.ResidualPGIDs = slices.Compact(r.ResidualPGIDs)
	slices.Sort(r.PendingStages)
	r.PendingStages = slices.Compact(r.PendingStages)
	r.Err = joined
	return r
}

func clonePoolCleanupResult(in PoolCleanupResult) PoolCleanupResult {
	in.ResidualPGIDs = append([]int(nil), in.ResidualPGIDs...)
	in.PendingStages = append([]string(nil), in.PendingStages...)
	return in
}

func (p *systemPool) beginDrain(force bool, generation uint64) *poolDrainFuture {
	p.mu.Lock()
	f := p.drainFuture
	if generation != p.generation {
		p.mu.Unlock()
		return completedPoolDrainFuture(generation, errors.New("stale pool generation"))
	}
	var retire []*systemWorkerTransport
	var waiters []chan poolCheckoutResult
	startSupervisorJoin := false
	if !f.started {
		f.started = true
		f.force = force
		p.closed = true
		p.superCancel()
		if p.attemptStop != nil {
			p.attemptStop()
		}
		f.supervisorPending = p.superStart
		startSupervisorJoin = f.supervisorPending
		for _, w := range p.workers {
			w.state = workerDead
			if w.transport != nil {
				p.registerTransportLocked(w.transport)
				retire = append(retire, w.transport)
			}
		}
		p.workers = nil
		waiters = p.waiters
		p.waiters = nil
	}
	if force && !f.force {
		f.force = true
	}
	if f.force {
		for w := range p.leased {
			delete(p.leased, w)
			if p.active > 0 {
				p.active--
			}
			w.state = workerDead
			if w.transport != nil {
				p.registerTransportLocked(w.transport)
				retire = append(retire, w.transport)
			}
		}
		f.leasedPending = 0
	} else {
		f.leasedPending = len(p.leased)
	}
	p.finalizeDrainLocked()
	p.mu.Unlock()
	for _, ch := range waiters {
		ch <- poolCheckoutResult{err: errSystemPoolClosed}
	}
	p.startTransportRetirements(retire)
	if startSupervisorJoin {
		go func() {
			<-p.superDone
			p.mu.Lock()
			f.supervisorPending = false
			p.finalizeDrainLocked()
			p.mu.Unlock()
		}()
	}
	return f
}

func completedPoolDrainFuture(generation uint64, err error) *poolDrainFuture {
	done := make(chan struct{})
	close(done)
	return &poolDrainFuture{done: done, generation: generation, finalized: true, result: PoolCleanupResult{Generation: generation, Err: err, Stage: "stale-generation"}}
}

func (p *systemPool) registerTransportLocked(t *systemWorkerTransport) *poolDrainEntry {
	if t == nil {
		return nil
	}
	f := p.drainFuture
	if f.finalized {
		return nil
	}
	if entry := f.entries[t]; entry != nil {
		return entry
	}
	f.nextSequence++
	entry := &poolDrainEntry{sequence: f.nextSequence, transport: t, pgid: t.pgid, done: make(chan struct{})}
	f.entries[t] = entry
	f.ordered = append(f.ordered, entry)
	return entry
}

func (p *systemPool) startTransportRetirements(transports []*systemWorkerTransport) {
	if len(transports) == 0 {
		return
	}
	unique := make([]*systemWorkerTransport, 0, len(transports))
	seen := make(map[*systemWorkerTransport]struct{}, len(transports))
	p.mu.Lock()
	for _, transport := range transports {
		if transport == nil {
			continue
		}
		p.registerTransportLocked(transport)
		if _, ok := seen[transport]; !ok {
			seen[transport] = struct{}{}
			unique = append(unique, transport)
		}
	}
	p.mu.Unlock()
	// Broadcast every TERM request before starting any caller-visible join.
	for _, transport := range unique {
		transport.requestAbort()
	}
	for _, transport := range unique {
		p.mu.Lock()
		entry := p.drainFuture.entries[transport]
		p.mu.Unlock()
		if entry == nil {
			// Registration closes atomically with finalization. A transport that
			// arrives after that fence still has an owned teardown, but cannot be
			// appended to the already-completed generation future.
			go func(transport *systemWorkerTransport) { _ = transport.waitAbort(context.Background()) }(transport)
			continue
		}
		entry.joinOnce.Do(func() {
			go func(entry *poolDrainEntry, transport *systemWorkerTransport) {
				err := transport.waitAbort(context.Background())
				p.mu.Lock()
				entry.err = err
				entry.residual = processGroupExists(entry.pgid)
				entry.terminal = true
				entry.transport = nil
				delete(p.drainFuture.entries, transport)
				close(entry.done)
				p.finalizeDrainLocked()
				p.mu.Unlock()
			}(entry, transport)
		})
	}
}

func (p *systemPool) retireTransports(transports []*systemWorkerTransport) {
	p.startTransportRetirements(transports)
	p.waitTransportRetirements(transports)
}

func (p *systemPool) waitTransportRetirements(transports []*systemWorkerTransport) {
	for _, transport := range transports {
		if transport == nil {
			continue
		}
		p.mu.Lock()
		entry := p.drainFuture.entries[transport]
		p.mu.Unlock()
		if entry != nil {
			<-entry.done
		}
	}
}

func (p *systemPool) finalizeDrainLocked() {
	f := p.drainFuture
	if f == nil || !f.started || f.finalized || f.supervisorPending || f.leasedPending != 0 {
		return
	}
	var joined error
	var residualPGIDs []int
	for _, entry := range f.ordered {
		if !entry.terminal {
			return
		}
		joined = errors.Join(joined, entry.err)
		if entry.residual && entry.pgid != 0 {
			residualPGIDs = append(residualPGIDs, entry.pgid)
		}
	}
	slices.Sort(residualPGIDs)
	residualPGIDs = slices.Compact(residualPGIDs)
	stage := "complete"
	if joined != nil {
		stage = "cleanup-error"
	}
	f.result = PoolCleanupResult{Generation: f.generation, Err: joined, ResidualPGIDs: residualPGIDs, Stage: stage}
	f.finalized = true
	close(f.done)
}

func (p *systemPool) invariantLocked() bool { return p.active == len(p.leased) }

func (p *systemPool) hasTransport() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, w := range p.workers {
		if w.transport != nil {
			return true
		}
	}
	return false
}

func newSystemPool(maxUses int, maxAge time.Duration, generations ...uint64) *systemPool {
	generation := uint64(1)
	if len(generations) > 0 && generations[0] != 0 {
		generation = generations[0]
	}
	return newConfiguredSystemPool(1, 1, maxUses, maxAge, generation)
}

func newConfiguredSystemPool(size, maxOverflow, maxUses int, maxAge time.Duration, generation uint64) *systemPool {
	if maxUses <= 0 {
		maxUses = 256
	}
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	if generation == 0 {
		generation = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &systemPool{
		maxUses: maxUses, maxAge: maxAge, generation: generation, size: size, maxOverflow: maxOverflow,
		leased:   map[*pooledWorker]struct{}{},
		superCtx: ctx, superCancel: cancel, superSignal: make(chan struct{}, 1),
		superDone: make(chan struct{}), backoffBase: 100 * time.Millisecond,
		jitterFn: func(delay time.Duration) time.Duration {
			jitter := time.Duration(rand.Uint64()%21) * delay / 100
			return min(30*time.Second, delay+jitter)
		},
		waitBackoff: func(ctx context.Context, delay time.Duration) bool {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-timer.C:
				return true
			}
		},
	}
	p.drainFuture = &poolDrainFuture{pool: p, done: make(chan struct{}), generation: generation, entries: make(map[*systemWorkerTransport]*poolDrainEntry)}
	p.drained = p.drainFuture.done
	return p
}

func (p *systemPool) capacityLocked() int { return p.size + p.maxOverflow }

func (p *systemPool) activate() {
	p.mu.Lock()
	p.activated = true
	p.requestReplenishLocked()
	p.mu.Unlock()
}

func (p *systemPool) publish(generation uint64, ready bool, now time.Time) error {
	p.mu.Lock()
	retired := p.pruneInvalidLocked(now)
	if p.closed || generation != p.generation {
		p.mu.Unlock()
		p.retireTransports(retired)
		return errors.New("stale pool generation")
	}
	if len(p.workers)+p.active >= p.capacityLocked() {
		p.mu.Unlock()
		p.retireTransports(retired)
		return errors.New("pool capacity exceeded")
	}
	if !ready {
		p.mu.Unlock()
		p.retireTransports(retired)
		return errors.New("worker is not ready")
	}
	p.workers = append(p.workers, &pooledWorker{state: workerIdle, generation: generation, started: now})
	retired = append(retired, p.wakeLocked(now)...)
	p.mu.Unlock()
	p.retireTransports(retired)
	return nil
}

func (p *systemPool) publishTransport(generation uint64, t *systemWorkerTransport, now time.Time) error {
	if t == nil {
		return errors.New("nil worker transport")
	}
	p.mu.Lock()
	retired := p.pruneInvalidLocked(now)
	if p.closed || generation != p.generation {
		entry := p.registerTransportLocked(t)
		if entry == nil {
			p.mu.Unlock()
			t.requestAbort()
			return errors.Join(errors.New("stale pool generation"), t.waitAbort(context.Background()))
		}
		retired = append(retired, t)
		p.mu.Unlock()
		p.retireTransports(retired)
		return errors.New("stale pool generation")
	}
	if len(p.workers)+p.active >= p.capacityLocked() {
		p.registerTransportLocked(t)
		retired = append(retired, t)
		p.mu.Unlock()
		p.retireTransports(retired)
		return errors.New("pool capacity exceeded")
	}
	p.workers = append(p.workers, &pooledWorker{state: workerIdle, generation: generation, started: now, transport: t})
	retired = append(retired, p.wakeLocked(now)...)
	p.mu.Unlock()
	p.retireTransports(retired)
	return nil
}

func (p *systemPool) checkout(ctx context.Context, now time.Time) (*pooledWorker, error) {
	for {
		p.mu.Lock()
		retired := p.pruneInvalidLocked(now)
		for i, w := range p.workers {
			if w.state == workerIdle {
				if err := ctx.Err(); err != nil {
					p.mu.Unlock()
					p.retireTransports(retired)
					return nil, err
				}
				w.state = workerLeased
				p.active++
				p.leased[w] = struct{}{}
				p.workers = append(p.workers[:i], p.workers[i+1:]...)
				p.mu.Unlock()
				p.retireTransports(retired)
				if p.beforeResultReturn != nil {
					p.beforeResultReturn()
				}
				if err := ctx.Err(); err != nil {
					p.returnUnused(w, time.Now())
					return nil, err
				}
				return w, nil
			}
		}
		if p.closed {
			p.mu.Unlock()
			p.retireTransports(retired)
			return nil, errSystemPoolClosed
		}
		if p.circuitOpen {
			p.mu.Unlock()
			p.retireTransports(retired)
			return nil, ErrCircuitOpen
		}
		ch := make(chan poolCheckoutResult, 1)
		p.waiters = append(p.waiters, ch)
		p.requestReplenishLocked()
		p.mu.Unlock()
		p.retireTransports(retired)
		select {
		case res := <-ch:
			if p.beforeResultReturn != nil {
				p.beforeResultReturn()
			}
			if err := ctx.Err(); err != nil {
				if res.worker != nil {
					p.returnUnused(res.worker, time.Now())
				}
				return nil, err
			}
			return res.worker, res.err
		case <-ctx.Done():
			if p.beforeCancelReconcile != nil {
				p.beforeCancelReconcile()
			}
			p.mu.Lock()
			removed := false
			for i, waiter := range p.waiters {
				if waiter == ch {
					p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
					removed = true
					break
				}
			}
			p.mu.Unlock()
			if !removed {
				// wakeLocked has removed this waiter and owns the buffered result;
				// reconcile synchronously so a lease can never be lost.
				res := <-ch
				if res.worker != nil {
					p.returnUnused(res.worker, time.Now())
				}
			}
			return nil, ctx.Err()
		}
	}
}

func (p *systemPool) release(w *pooledWorker, resultSeen bool, now time.Time) {
	p.finishLease(w, resultSeen, true, now)
}

func (p *systemPool) returnUnused(w *pooledWorker, now time.Time) {
	p.finishLease(w, false, false, now)
}

func (p *systemPool) finishLease(w *pooledWorker, resultSeen, used bool, now time.Time) {
	if w == nil {
		return
	}
	var abort *systemWorkerTransport
	p.mu.Lock()
	if _, owned := p.leased[w]; !owned {
		p.mu.Unlock()
		return
	}
	if used {
		w.uses++
	}
	delete(p.leased, w)
	if p.active > 0 {
		p.active--
	}
	if p.drainFuture.started && !p.drainFuture.force {
		p.drainFuture.leasedPending = len(p.leased)
	}
	if resultSeen {
		w.state = workerResultSeen
	}
	if p.closed || p.circuitOpen || w.generation != p.generation || w.uses >= p.maxUses || now.Sub(w.started) >= p.maxAge {
		w.state = workerRetiring
		abort = w.transport
		w.state = workerDead
		canReplenish := !p.closed && w.generation == p.generation
		if canReplenish {
			p.requestReplenishLocked()
		}
		p.registerTransportLocked(abort)
		p.finalizeDrainLocked()
		p.mu.Unlock()
		p.retireTransports([]*systemWorkerTransport{abort})
		return
	}
	w.state = workerResetting
	w.state = workerIdle
	p.workers = append(p.workers, w)
	invalid := p.wakeLocked(now)
	p.mu.Unlock()
	p.retireTransports(invalid)
}

func (p *systemPool) poison(w *pooledWorker) {
	if w == nil {
		return
	}
	p.mu.Lock()
	if _, owned := p.leased[w]; !owned {
		p.mu.Unlock()
		return
	}
	delete(p.leased, w)
	if p.active > 0 {
		p.active--
	}
	w.state = workerDead
	if p.drainFuture.started && !p.drainFuture.force {
		p.drainFuture.leasedPending = len(p.leased)
	}
	canReplenish := !p.closed && w.generation == p.generation
	if canReplenish {
		p.requestReplenishLocked()
	}
	p.registerTransportLocked(w.transport)
	p.finalizeDrainLocked()
	p.mu.Unlock()
	p.retireTransports([]*systemWorkerTransport{w.transport})
}

func (p *systemPool) setCircuitOpen(open bool) {
	p.mu.Lock()
	p.circuitOpen = open
	if open && p.attemptStop != nil {
		p.attemptStop()
	}
	if !open {
		p.requestReplenishLocked()
	}
	var idle []*pooledWorker
	var waiters []chan poolCheckoutResult
	if open {
		idle = append(idle, p.workers...)
		p.workers = nil
		waiters = p.waiters
		p.waiters = nil
		for _, w := range idle {
			w.state = workerDead
			p.registerTransportLocked(w.transport)
		}
	}
	p.mu.Unlock()
	for _, waiter := range waiters {
		waiter <- poolCheckoutResult{err: ErrCircuitOpen}
	}
	var retired []*systemWorkerTransport
	for _, w := range idle {
		if w.transport != nil {
			retired = append(retired, w.transport)
		}
	}
	p.retireTransports(retired)
}

func (p *systemPool) requestReplenishLocked() {
	if p.closed || p.circuitOpen || p.replenishFn == nil {
		return
	}
	if !p.superStart {
		p.superStart = true
		go p.replenishSupervisor()
	}
	select {
	case p.superSignal <- struct{}{}:
	default:
	}
}

func (p *systemPool) replenishSupervisor() {
	defer close(p.superDone)
	attempt := 0
	for {
		select {
		case <-p.superCtx.Done():
			return
		case <-p.superSignal:
		}
		for {
			p.mu.Lock()
			desired := 1
			if p.activated {
				desired = p.size
			}
			if len(p.waiters) > 0 {
				desired = min(desired+p.maxOverflow, p.capacityLocked())
			}
			retired := p.pruneInvalidLocked(time.Now())
			owned := len(p.workers) + p.active + p.starting
			if p.closed || p.circuitOpen || p.replenishFn == nil || owned >= desired {
				p.mu.Unlock()
				p.retireTransports(retired)
				attempt = 0
				break
			}
			fn, generation := p.replenishFn, p.generation
			attemptCtx, attemptCancel := context.WithCancel(p.superCtx)
			p.attemptStop = attemptCancel
			p.starting++
			p.mu.Unlock()
			p.retireTransports(retired)

			nw, err := fn(attemptCtx, generation)
			attemptCancel()
			p.mu.Lock()
			p.attemptStop = nil
			if p.starting > 0 {
				p.starting--
			}
			valid := err == nil && nw != nil && !p.closed && !p.circuitOpen && p.generation == generation && len(p.workers)+p.active < p.capacityLocked()
			if valid {
				nw.state = workerIdle
				nw.generation = generation
			} else if nw != nil {
				p.registerTransportLocked(nw.transport)
			}
			failureFn, successFn := p.failureFn, p.successFn
			recordFailure := err != nil && failureFn != nil && !errors.Is(err, context.Canceled)
			recordSuccess := valid && successFn != nil
			p.mu.Unlock()
			pendingRetirements := retired
			retired = nil
			if !valid && nw != nil && nw.transport != nil {
				pendingRetirements = append(pendingRetirements, nw.transport)
			}
			p.startTransportRetirements(pendingRetirements)
			if recordFailure {
				failureFn(generation)
			}
			p.waitTransportRetirements(pendingRetirements)
			if valid {
				if recordSuccess {
					successFn(generation)
				}
				p.mu.Lock()
				valid = !p.closed && !p.circuitOpen && p.generation == generation && len(p.workers)+p.active < p.capacityLocked()
				if valid {
					p.workers = append(p.workers, nw)
					retired = append(retired, p.wakeLocked(time.Now())...)
				}
				p.mu.Unlock()
			}
			p.retireTransports(retired)
			if valid {
				attempt = 0
				continue
			}
			if (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) && p.superCtx.Err() != nil {
				return
			}
			attempt++
			delay := p.backoffBase << min(attempt-1, 8)
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			if p.jitterFn != nil {
				delay = p.jitterFn(delay)
			}
			if !p.waitBackoff(p.superCtx, delay) {
				return
			}
		}
	}
}

func (p *systemPool) drain(generation uint64) {
	p.abortClose(generation)
}

// gracefulDrain closes admission, aborts idle workers, and lets leased work
// finish. Leased workers retire on release and are never replenished.
func (p *systemPool) gracefulDrain(generation uint64) <-chan struct{} {
	return p.beginDrain(false, generation).done
}

// abortClose immediately revokes idle and leased workers; all waits happen
// outside the mutex so pool callers cannot deadlock on process reaping.
func (p *systemPool) abortClose(generation uint64) {
	_ = p.beginDrain(true, generation).wait(context.Background())
}

func (p *systemPool) cleanupError() error {
	return p.drainFuture.wait(context.Background()).Err
}

func (p *systemPool) wakeLocked(now time.Time) []*systemWorkerTransport {
	retired := p.pruneInvalidLocked(now)
	if p.circuitOpen {
		for _, w := range p.workers {
			w.state = workerDead
			if w.transport != nil {
				p.registerTransportLocked(w.transport)
				retired = append(retired, w.transport)
			}
		}
		p.workers = nil
		return retired
	}
	if len(p.waiters) == 0 || len(p.workers) == 0 {
		return retired
	}
	w := p.workers[0]
	p.workers = p.workers[1:]
	w.state = workerLeased
	p.active++
	p.leased[w] = struct{}{}
	ch := p.waiters[0]
	p.waiters = p.waiters[1:]
	ch <- poolCheckoutResult{worker: w}
	return retired
}

func (p *systemPool) pruneInvalidLocked(now time.Time) []*systemWorkerTransport {
	kept := p.workers[:0]
	var retired []*systemWorkerTransport
	for _, w := range p.workers {
		if w == nil || w.state != workerIdle || w.generation != p.generation || w.uses >= p.maxUses || now.Sub(w.started) >= p.maxAge {
			if w != nil {
				w.state = workerDead
				if w.transport != nil {
					p.registerTransportLocked(w.transport)
					retired = append(retired, w.transport)
				}
			}
			continue
		}
		kept = append(kept, w)
	}
	p.workers = kept
	if len(retired) > 0 {
		p.requestReplenishLocked()
	}
	return retired
}
