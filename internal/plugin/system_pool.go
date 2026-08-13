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
}

// systemPool provides generation-fenced FIFO leases. Process transport is
// deliberately supplied by the runner; this type owns lifecycle invariants.
type systemPool struct {
	mu         sync.Mutex
	generation uint64
	workers    []*pooledWorker
	waiters    []chan *pooledWorker
	maxUses    int
	maxAge     time.Duration
	closed     bool
}

func newSystemPool(maxUses int, maxAge time.Duration) *systemPool {
	if maxUses <= 0 {
		maxUses = 256
	}
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	return &systemPool{maxUses: maxUses, maxAge: maxAge, generation: 1}
}

func (p *systemPool) publish(generation uint64, ready bool, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || generation != p.generation {
		return errors.New("stale pool generation")
	}
	if !ready {
		return errors.New("worker is not ready")
	}
	p.workers = append(p.workers, &pooledWorker{state: workerIdle, generation: generation, started: now})
	p.wakeLocked()
	return nil
}

func (p *systemPool) checkout(ctx context.Context, now time.Time) (*pooledWorker, error) {
	for {
		p.mu.Lock()
		for i, w := range p.workers {
			if w.state == workerIdle && w.generation == p.generation && now.Sub(w.started) < p.maxAge && w.uses < p.maxUses {
				w.state = workerLeased
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
	if resultSeen {
		w.state = workerResultSeen
	}
	if p.closed || w.generation != p.generation || w.uses >= p.maxUses || now.Sub(w.started) >= p.maxAge {
		w.state = workerRetiring
		w.state = workerDead
		return
	}
	w.state = workerResetting
	w.state = workerIdle
	p.workers = append(p.workers, w)
	p.wakeLocked()
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
	ch := p.waiters[0]
	p.waiters = p.waiters[1:]
	ch <- w
}
