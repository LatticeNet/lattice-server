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
	waiters     []chan *pooledWorker
	maxUses     int
	maxAge      time.Duration
	maxOverflow int
	closed      bool
	replenishFn func(uint64) (*pooledWorker, error)
	active      int
	leased      map[*pooledWorker]struct{}
}

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
			return nil, errors.New("pool closed")
		}
		ch := make(chan *pooledWorker, 1)
		p.waiters = append(p.waiters, ch)
		p.mu.Unlock()
		select {
		case w := <-ch:
			return w, nil
		case <-ctx.Done():
			p.mu.Lock()
			for i, waiter := range p.waiters {
				if waiter == ch {
					p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
					break
				}
			}
			p.mu.Unlock()
			return nil, ctx.Err()
		}
	}
}

func (p *systemPool) release(w *pooledWorker, resultSeen bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
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
		if w.transport != nil {
			_ = w.transport.abort()
		}
		w.state = workerDead
		if p.replenishFn != nil {
			go func(gen uint64) {
				if nw, err := p.replenishFn(gen); err == nil && nw != nil {
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
}

func (p *systemPool) poison(w *pooledWorker) {
	if w == nil {
		return
	}
	if w.transport != nil {
		_ = w.transport.abort()
	}
	p.mu.Lock()
	if p.active > 0 {
		p.active--
	}
	w.state = workerDead
	p.mu.Unlock()
	if p.replenishFn != nil {
		if nw, err := p.replenishFn(p.generation); err == nil && nw != nil {
			if err := p.publishTransport(p.generation, nw.transport, time.Now()); err != nil && nw.transport != nil {
				_ = nw.transport.abort()
			}
		}
	}
}

func (p *systemPool) drain(generation uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation != p.generation {
		return
	}
	p.generation++
	for _, w := range p.workers {
		w.state = workerRetiring
		if w.transport != nil {
			_ = w.transport.abort()
		}
		w.state = workerDead
	}
	p.workers = nil
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
	ch <- w
}
