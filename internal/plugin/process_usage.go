package plugin

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// processPeakSchedule is when a new plugin process's own peak resident set
// is read after the first look at start: densely at first, because most
// per-invocation processes answer and exit within a second, then every
// processPeakInterval while it runs. One small /proc read each.
var processPeakSchedule = []time.Duration{
	10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond,
}

const processPeakInterval = time.Second

// processPeak follows one plugin process's own peak resident set while it
// runs. The exit rusage cannot give it on Linux: exec records the replaced
// address space's high-water mark in the child's ru_maxrss, and Go starts
// children on lattice-server's address space (CLONE_VM), so every plugin
// process would report lattice-server's peak. VmHWM belongs to the address
// space exec created, so the largest sample is the process's own peak up to
// the last sample: a lower bound that misses only growth after it. A nil
// *processPeak samples nothing.
type processPeak struct {
	pid     int
	max     atomic.Int64
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// watchProcessPeak starts sampling pid, or returns nil where the platform
// has no per-process high-water mark to read. Call it only after the process
// has started, and call finish once it has been reaped.
func watchProcessPeak(pid int) *processPeak {
	if !processPeakFromProc {
		return nil
	}
	p := &processPeak{pid: pid, stop: make(chan struct{}), stopped: make(chan struct{})}
	p.read()
	go p.run()
	return p
}

func (p *processPeak) run() {
	defer close(p.stopped)
	timer := time.NewTimer(processPeakSchedule[0])
	defer timer.Stop()
	for i := 1; ; i++ {
		select {
		case <-p.stop:
			return
		case <-timer.C:
			p.read()
			next := processPeakInterval
			if i < len(processPeakSchedule) {
				next = processPeakSchedule[i] - processPeakSchedule[i-1]
			}
			timer.Reset(next)
		}
	}
}

// sample reads the process's high-water mark once, out of schedule, unless
// the sampler has finished. A process that already exited reads as nothing
// and leaves the peak as it was. The pid stays reserved until the process
// is reaped, and finish runs right after the reap, so a read of a reused pid
// would need the kernel to hand the same pid out again inside that gap.
func (p *processPeak) sample() {
	if p == nil {
		return
	}
	select {
	case <-p.stop:
		return
	default:
	}
	p.read()
}

func (p *processPeak) read() {
	v := readVmHWMBytes(p.pid)
	for {
		cur := p.max.Load()
		if v <= cur || p.max.CompareAndSwap(cur, v) {
			return
		}
	}
}

// finish stops the sampler, waits for it, and returns the largest sample.
// It may be called more than once.
func (p *processPeak) finish() int64 {
	if p == nil {
		return 0
	}
	p.once.Do(func() { close(p.stop) })
	<-p.stopped
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
