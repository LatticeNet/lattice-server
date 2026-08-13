package plugin

import (
	"context"
	"errors"
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
	replenishFn func(uint64) (*pooledWorker, error)
	active      int
	leased      map[*pooledWorker]struct{}
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
	return &systemPool{maxUses: maxUses, maxAge: maxAge, generation: generation, maxOverflow: 1, leased: map[*pooledWorker]struct{}{}}
}

func (p *systemPool) publish(generation uint64, ready bool, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || generation != p.generation {
		return errors.New("stale pool generation")
	}
	if len(p.workers)+p.active >= 1+p.maxOverflow {
		return errors.New("pool capacity exceeded")
	}
	if !ready {
		return errors.New("worker is not ready")
	}
	p.workers = append(p.workers, &pooledWorker{state: workerIdle, generation: generation, started: now})
	p.wakeLocked()
	return nil
}

func (p *systemPool) publishTransport(generation uint64, t *systemWorkerTransport, now time.Time) error {
	if t == nil {
		return errors.New("nil worker transport")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || generation != p.generation {
		return errors.New("stale pool generation")
	}
	if len(p.workers)+p.active >= 1+p.maxOverflow {
		return errors.New("pool capacity exceeded")
	}
	p.workers = append(p.workers, &pooledWorker{state: workerIdle, generation: generation, started: now, transport: t})
	p.wakeLocked()
	return nil
}

func (p *systemPool) checkout(ctx context.Context, now time.Time) (*pooledWorker, error) {
	for {
		p.mu.Lock()
		for i, w := range p.workers {
			if w.state == workerIdle && w.generation == p.generation && now.Sub(w.started) < p.maxAge && w.uses < p.maxUses {
				w.state = workerLeased
				p.active++
				p.leased[w] = struct{}{}
				p.workers = append(p.workers[:i], p.workers[i+1:]...)
				p.mu.Unlock()
				return w, nil
			}
		}
		if p.closed {
			p.mu.Unlock()
			return nil, errSystemPoolClosed
		}
		// Materialize one bounded overflow worker when all capacity is leased.
		if p.replenishFn != nil && len(p.workers)+p.active < 1+p.maxOverflow {
			fn, gen := p.replenishFn, p.generation
			p.mu.Unlock()
			if nw, err := fn(gen); err == nil && nw != nil {
				if err := p.publishTransport(gen, nw.transport, time.Now()); err != nil && nw.transport != nil {
					_ = nw.transport.abort()
				}
			}
			continue
		}
		ch := make(chan poolCheckoutResult, 1)
		p.waiters = append(p.waiters, ch)
		p.mu.Unlock()
		select {
		case res := <-ch:
			return res.worker, res.err
		case <-ctx.Done():
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
					p.release(res.worker, false, time.Now())
				}
			}
			return nil, ctx.Err()
		}
	}
}

func (p *systemPool) release(w *pooledWorker, resultSeen bool, now time.Time) {
	var abort *systemWorkerTransport
	p.mu.Lock()
	w.uses++
	if p.active > 0 {
		p.active--
	}
	delete(p.leased, w)
	if resultSeen {
		w.state = workerResultSeen
	}
	if p.closed || w.generation != p.generation || w.uses >= p.maxUses || now.Sub(w.started) >= p.maxAge {
		w.state = workerRetiring
		abort = w.transport
		w.state = workerDead
		fn, gen := p.replenishFn, p.generation
		canReplenish := !p.closed && w.generation == gen
		p.mu.Unlock()
		if abort != nil {
			_ = abort.abort()
		}
		if canReplenish && fn != nil {
			go func(gen uint64) {
				if nw, err := fn(gen); err == nil && nw != nil {
					if err := p.publishTransport(gen, nw.transport, time.Now()); err != nil && nw.transport != nil {
						_ = nw.transport.abort()
					}
				}
			}(w.generation)
		}
		return
	}
	w.state = workerResetting
	w.state = workerIdle
	p.workers = append(p.workers, w)
	p.wakeLocked()
	p.mu.Unlock()
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
	fn, gen := p.replenishFn, p.generation
	canReplenish := !p.closed && w.generation == gen
	p.mu.Unlock()
	if w.transport != nil {
		_ = w.transport.abort()
	}
	if canReplenish && fn != nil {
		if nw, err := fn(gen); err == nil && nw != nil {
			if err := p.publishTransport(gen, nw.transport, time.Now()); err != nil && nw.transport != nil {
				_ = nw.transport.abort()
			}
		}
	}
}

func (p *systemPool) drain(generation uint64) {
	p.abortClose(generation)
}

// gracefulDrain closes admission, aborts idle workers, and lets leased work
// finish. Leased workers retire on release and are never replenished.
func (p *systemPool) gracefulDrain(generation uint64) {
	p.mu.Lock()
	if generation != p.generation {
		p.mu.Unlock()
		return
	}
	p.closed = true
	idle := append([]*pooledWorker(nil), p.workers...)
	for _, w := range idle {
		w.state = workerDead
	}
	p.workers = nil
	waiters := p.waiters
	p.waiters = nil
	p.mu.Unlock()
	for _, ch := range waiters {
		ch <- poolCheckoutResult{err: errSystemPoolClosed}
	}
	for _, w := range idle {
		if w.transport != nil {
			_ = w.transport.abort()
		}
	}
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
	for _, ch := range waiters {
		ch <- poolCheckoutResult{err: errSystemPoolClosed}
	}
	for _, w := range all {
		if w.transport != nil {
			_ = w.transport.abort()
		}
	}
}

func (p *systemPool) wakeLocked() {
	if len(p.waiters) == 0 || len(p.workers) == 0 {
		return
	}
	w := p.workers[0]
	p.workers = p.workers[1:]
	w.state = workerLeased
	p.active++
	p.leased[w] = struct{}{}
	ch := p.waiters[0]
	p.waiters = p.waiters[1:]
	ch <- poolCheckoutResult{worker: w}
}
