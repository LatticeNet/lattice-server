package plugin

import (
	"context"
	"errors"
	"math/rand/v2"
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
	maxOverflow int
	closed      bool
	replenishFn func(context.Context, uint64) (*pooledWorker, error)
	failureFn   func(uint64)
	successFn   func(uint64)
	active      int
	starting    int
	drained     chan struct{}
	drainOnce   sync.Once
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
	if maxUses <= 0 {
		maxUses = 256
	}
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	generation := uint64(1)
	if len(generations) > 0 && generations[0] != 0 {
		generation = generations[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &systemPool{
		maxUses: maxUses, maxAge: maxAge, generation: generation, maxOverflow: 1,
		leased: map[*pooledWorker]struct{}{}, drained: make(chan struct{}),
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
}

func (p *systemPool) publish(generation uint64, ready bool, now time.Time) error {
	p.mu.Lock()
	retired := p.pruneInvalidLocked(now)
	if p.closed || generation != p.generation {
		p.mu.Unlock()
		abortTransports(retired)
		return errors.New("stale pool generation")
	}
	if len(p.workers)+p.active >= 1+p.maxOverflow {
		p.mu.Unlock()
		abortTransports(retired)
		return errors.New("pool capacity exceeded")
	}
	if !ready {
		p.mu.Unlock()
		abortTransports(retired)
		return errors.New("worker is not ready")
	}
	p.workers = append(p.workers, &pooledWorker{state: workerIdle, generation: generation, started: now})
	retired = append(retired, p.wakeLocked(now)...)
	p.mu.Unlock()
	abortTransports(retired)
	return nil
}

func (p *systemPool) publishTransport(generation uint64, t *systemWorkerTransport, now time.Time) error {
	if t == nil {
		return errors.New("nil worker transport")
	}
	p.mu.Lock()
	retired := p.pruneInvalidLocked(now)
	if p.closed || generation != p.generation {
		p.mu.Unlock()
		abortTransports(retired)
		return errors.New("stale pool generation")
	}
	if len(p.workers)+p.active >= 1+p.maxOverflow {
		p.mu.Unlock()
		abortTransports(retired)
		return errors.New("pool capacity exceeded")
	}
	p.workers = append(p.workers, &pooledWorker{state: workerIdle, generation: generation, started: now, transport: t})
	retired = append(retired, p.wakeLocked(now)...)
	p.mu.Unlock()
	abortTransports(retired)
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
					abortTransports(retired)
					return nil, err
				}
				w.state = workerLeased
				p.active++
				p.leased[w] = struct{}{}
				p.workers = append(p.workers[:i], p.workers[i+1:]...)
				p.mu.Unlock()
				abortTransports(retired)
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
			abortTransports(retired)
			return nil, errSystemPoolClosed
		}
		if p.circuitOpen {
			p.mu.Unlock()
			abortTransports(retired)
			return nil, ErrCircuitOpen
		}
		ch := make(chan poolCheckoutResult, 1)
		p.waiters = append(p.waiters, ch)
		p.requestReplenishLocked()
		p.mu.Unlock()
		abortTransports(retired)
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
	var abort *systemWorkerTransport
	closeDrained := false
	p.mu.Lock()
	if used {
		w.uses++
	}
	if p.active > 0 {
		p.active--
	}
	delete(p.leased, w)
	if p.closed && p.active == 0 {
		closeDrained = true
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
		p.mu.Unlock()
		if abort != nil {
			_ = abort.abort()
		}
		if closeDrained {
			p.closeDrained()
		}
		return
	}
	w.state = workerResetting
	w.state = workerIdle
	p.workers = append(p.workers, w)
	invalid := p.wakeLocked(now)
	p.mu.Unlock()
	abortTransports(invalid)
}

func (p *systemPool) poison(w *pooledWorker) {
	if w == nil {
		return
	}
	p.mu.Lock()
	if p.active > 0 {
		p.active--
	}
	w.state = workerDead
	delete(p.leased, w)
	closeDrained := p.closed && p.active == 0
	canReplenish := !p.closed && w.generation == p.generation
	if canReplenish {
		p.requestReplenishLocked()
	}
	p.mu.Unlock()
	if w.transport != nil {
		_ = w.transport.abort()
	}
	if closeDrained {
		p.closeDrained()
	}
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
		}
	}
	p.mu.Unlock()
	for _, waiter := range waiters {
		waiter <- poolCheckoutResult{err: ErrCircuitOpen}
	}
	for _, w := range idle {
		if w.transport != nil {
			_ = w.transport.abort()
		}
	}
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
			if len(p.waiters) > 0 {
				desired += p.maxOverflow
			}
			retired := p.pruneInvalidLocked(time.Now())
			owned := len(p.workers) + p.active + p.starting
			if p.closed || p.circuitOpen || p.replenishFn == nil || owned >= desired {
				p.mu.Unlock()
				abortTransports(retired)
				attempt = 0
				break
			}
			fn, generation := p.replenishFn, p.generation
			attemptCtx, attemptCancel := context.WithCancel(p.superCtx)
			p.attemptStop = attemptCancel
			p.starting++
			p.mu.Unlock()
			abortTransports(retired)

			nw, err := fn(attemptCtx, generation)
			attemptCancel()
			p.mu.Lock()
			p.attemptStop = nil
			if p.starting > 0 {
				p.starting--
			}
			valid := err == nil && nw != nil && !p.closed && !p.circuitOpen && p.generation == generation && len(p.workers)+p.active < 1+p.maxOverflow
			if valid {
				nw.state = workerIdle
				nw.generation = generation
			}
			failureFn, successFn := p.failureFn, p.successFn
			recordFailure := err != nil && failureFn != nil && !errors.Is(err, context.Canceled)
			recordSuccess := valid && successFn != nil
			p.mu.Unlock()
			if recordFailure {
				failureFn(generation)
			}
			if valid {
				if recordSuccess {
					successFn(generation)
				}
				p.mu.Lock()
				valid = !p.closed && !p.circuitOpen && p.generation == generation && len(p.workers)+p.active < 1+p.maxOverflow
				if valid {
					p.workers = append(p.workers, nw)
					retired = append(retired, p.wakeLocked(time.Now())...)
				}
				p.mu.Unlock()
			}
			abortTransports(retired)
			if !valid && nw != nil && nw.transport != nil {
				_ = nw.transport.abort()
			}
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
	p.mu.Lock()
	if generation != p.generation {
		done := p.drained
		p.mu.Unlock()
		return done
	}
	p.closed = true
	p.superCancel()
	if p.attemptStop != nil {
		p.attemptStop()
	}
	superStarted := p.superStart
	idle := append([]*pooledWorker(nil), p.workers...)
	for _, w := range idle {
		w.state = workerDead
	}
	p.workers = nil
	waiters := p.waiters
	p.waiters = nil
	p.mu.Unlock()
	if superStarted {
		<-p.superDone
	}
	for _, ch := range waiters {
		ch <- poolCheckoutResult{err: errSystemPoolClosed}
	}
	for _, w := range idle {
		if w.transport != nil {
			_ = w.transport.abort()
		}
	}
	p.mu.Lock()
	closeNow := p.active == 0
	p.mu.Unlock()
	if closeNow {
		p.closeDrained()
	}
	return p.drained
}

// abortClose immediately revokes idle and leased workers; all waits happen
// outside the mutex so pool callers cannot deadlock on process reaping.
func (p *systemPool) abortClose(generation uint64) {
	p.mu.Lock()
	if generation != p.generation {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.superCancel()
	if p.attemptStop != nil {
		p.attemptStop()
	}
	superStarted := p.superStart
	all := append([]*pooledWorker(nil), p.workers...)
	for w := range p.leased {
		w.state = workerDead
		all = append(all, w)
	}
	for _, w := range p.workers {
		w.state = workerDead
	}
	p.workers = nil
	p.leased = map[*pooledWorker]struct{}{}
	p.active = 0
	waiters := p.waiters
	p.waiters = nil
	p.mu.Unlock()
	if superStarted {
		<-p.superDone
	}
	for _, ch := range waiters {
		ch <- poolCheckoutResult{err: errSystemPoolClosed}
	}
	for _, w := range all {
		if w.transport != nil {
			_ = w.transport.abort()
		}
	}
	p.closeDrained()
}

func (p *systemPool) closeDrained() {
	p.drainOnce.Do(func() { close(p.drained) })
}

func (p *systemPool) wakeLocked(now time.Time) []*systemWorkerTransport {
	retired := p.pruneInvalidLocked(now)
	if p.circuitOpen {
		for _, w := range p.workers {
			w.state = workerDead
			if w.transport != nil {
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

func abortTransports(transports []*systemWorkerTransport) {
	for _, transport := range transports {
		_ = transport.abort()
	}
}
