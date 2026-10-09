package plugin

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// processPeakInterval is how often a running plugin process's own peak
// resident set is read. One small /proc read per live plugin process.
const processPeakInterval = time.Second

// processPeak follows one plugin process's own peak resident set while it
// runs. The exit rusage cannot give it on Linux: exec records the replaced
// address space's high-water mark in the child's ru_maxrss, and Go starts
// children on lattice-server's address space (CLONE_VM), so every plugin
// process would report lattice-server's peak. VmHWM belongs to the address
// space exec created, so the largest sample is the process's own peak up to
// the last sample. A nil *processPeak samples nothing.
type processPeak struct {
	pid  int
	max  atomic.Int64
	stop chan struct{}
	once sync.Once
}

// watchProcessPeak starts sampling pid, or returns nil where the platform
// has no per-process high-water mark to read.
func watchProcessPeak(pid int) *processPeak {
	if !processPeakFromProc {
		return nil
	}
	p := &processPeak{pid: pid, stop: make(chan struct{})}
	p.sample()
	go func() {
		t := time.NewTicker(processPeakInterval)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				p.sample()
			}
		}
	}()
	return p
}

// sample reads the process's high-water mark once. A process that already
// exited reads as nothing and leaves the peak as it was.
func (p *processPeak) sample() {
	if p == nil {
		return
	}
	v := readVmHWMBytes(p.pid)
	for {
		cur := p.max.Load()
		if v <= cur || p.max.CompareAndSwap(cur, v) {
			return
		}
	}
}

// finish stops the sampler and returns the largest sample.
func (p *processPeak) finish() int64 {
	if p == nil {
		return 0
	}
	p.once.Do(func() { close(p.stop) })
	return p.max.Load()
}

// processExitFor returns the hook that reports a plugin process's resources
// to the runner's ProcessObserver, or nil when there is none. sampledPeak is
// the process's own peak from its processPeak; where the platform has none,
// the exit rusage is used instead.
func (r *SystemRunner) processExitFor(pluginID string) func(state *os.ProcessState, sampledPeak int64) {
	obs := r.opts.ProcessObserver
	if obs == nil {
		return nil
	}
	return func(state *os.ProcessState, sampledPeak int64) {
		if state == nil {
			return
		}
		rss := sampledPeak
		if !processPeakFromProc {
			if ru, ok := state.SysUsage().(*syscall.Rusage); ok && ru != nil {
				rss = rusageMaxRSSBytes(ru)
			}
		}
		obs(pluginID, state.UserTime()+state.SystemTime(), rss)
	}
}
