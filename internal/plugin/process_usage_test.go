package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type recordedExit struct {
	pluginID string
	cpu      time.Duration
	rss      int64
}

func TestProcessExitReportsKernelAccounting(t *testing.T) {
	var got []recordedExit
	r := &SystemRunner{opts: SystemRunnerOptions{ProcessObserver: func(id string, cpu time.Duration, rss int64) {
		got = append(got, recordedExit{id, cpu, rss})
	}}}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	const sampled = 5 << 20
	r.processExitFor("latticenet.example")(cmd.ProcessState, sampled)
	if len(got) != 1 || got[0].pluginID != "latticenet.example" {
		t.Fatalf("observed %+v", got)
	}
	if got[0].cpu <= 0 {
		t.Fatalf("a Go test binary used %v CPU; want it measured", got[0].cpu)
	}
	// Linux reports the sampled peak, never the exit rusage (see processPeak);
	// elsewhere the rusage is all there is.
	if processPeakFromProc && got[0].rss != sampled {
		t.Fatalf("peak %d; want the sampled %d", got[0].rss, sampled)
	}
	if !processPeakFromProc && got[0].rss < 1<<20 {
		t.Fatalf("a Go test binary peaked at %d bytes; want it measured", got[0].rss)
	}
	// No observer: no hook, so the runner adds nothing to a process exit.
	if (&SystemRunner{}).processExitFor("p") != nil {
		t.Fatal("hook without an observer")
	}
}

func TestPooledWorkerReportsItsExit(t *testing.T) {
	var mu sync.Mutex
	var states []*os.ProcessState
	dir := filepath.Join(t.TempDir(), "w")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
	worker, err := startSystemWorkerObserved(t.Context(), os.Args[0], dir, env, func(st *os.ProcessState, _ int64) {
		mu.Lock()
		states = append(states, st)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.awaitReadyContext(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	_ = worker.abort()
	select {
	case <-worker.waitDone:
	case <-time.After(10 * time.Second):
		t.Fatal("worker was not reaped")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(states) != 1 || states[0] == nil {
		t.Fatalf("exit observed %d times", len(states))
	}
}

// exitRecorder collects ProcessObserver calls for the runner tests below.
type exitRecorder struct {
	mu   sync.Mutex
	got  []recordedExit
	seen chan struct{}
}

func newExitRecorder() *exitRecorder { return &exitRecorder{seen: make(chan struct{}, 16)} }

func (r *exitRecorder) observe(id string, cpu time.Duration, rss int64) {
	r.mu.Lock()
	r.got = append(r.got, recordedExit{id, cpu, rss})
	r.mu.Unlock()
	r.seen <- struct{}{}
}

func (r *exitRecorder) wait(t *testing.T, n int) []recordedExit {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-r.seen:
		case <-time.After(10 * time.Second):
			r.mu.Lock()
			defer r.mu.Unlock()
			t.Fatalf("saw %d process exits, want %d: %+v", len(r.got), n, r.got)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedExit(nil), r.got...)
}

// TestSystemRunnerReportsAnInvocationProcess runs one per-invocation (v1)
// plugin process through the runner and expects the observer to hear its
// exit under the plugin's id.
func TestSystemRunnerReportsAnInvocationProcess(t *testing.T) {
	rec := newExitRecorder()
	r := newRunner(t, SystemRunnerOptions{ProcessObserver: rec.observe})
	loaded := makeBundle(t, "p.observed", "#!/bin/sh\nread line\necho '{\"ok\":true}'\n", "")
	resp, err := startInvoke(t, r, loaded, "plan", nil)
	if err != nil || !resp.OK {
		t.Fatalf("Invoke = %+v, %v", resp, err)
	}
	got := rec.wait(t, 1)
	if len(got) != 1 || got[0].pluginID != "p.observed" {
		t.Fatalf("observed %+v, want one exit of p.observed", got)
	}
}

// TestSystemRunnerReportsPooledWorkers prepares a pool of two warm (v2)
// workers through the runner: the first started by Prepare, the second by
// the pool's own replenishment after activation. Stopping the plugin retires
// both, and the observer hears both exits.
func TestSystemRunnerReportsPooledWorkers(t *testing.T) {
	t.Setenv("LATTICE_TEST_V2_HELPER", "1")
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	bundleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundleDir, artifactFileName), binary, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := Loaded{
		Manifest:   Manifest{ID: "p.pool-observed", Name: "pool observed", Type: TypeSystem, Runtime: &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV2}},
		BundlePath: bundleDir,
	}
	rec := newExitRecorder()
	cfg := SystemPoolConfig{Size: 2, MaxOverflow: 0, StartTimeout: 5 * time.Second, MaxUses: 256, MaxAge: time.Hour}
	runner, err := NewSystemRunner(SystemRunnerOptions{
		RuntimeDir: t.TempDir(), EnvAllowlist: []string{"LATTICE_TEST_V2_HELPER"}, Pool: &cfg, ProcessObserver: rec.observe,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	if err := runner.ActivateGeneration(loaded.Manifest.ID, 1); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	p := runner.st[loaded.Manifest.ID][1].pool
	runner.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		workers, starting := len(p.workers), p.starting
		p.mu.Unlock()
		if workers == 2 && starting == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool has %d workers (%d starting), want 2 ready", workers, starting)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := runner.Stop(t.Context(), RunnerStopRequest{PluginID: loaded.Manifest.ID, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	got := rec.wait(t, 2)
	for _, e := range got {
		if e.pluginID != loaded.Manifest.ID {
			t.Fatalf("observed %+v, want both exits under %s", got, loaded.Manifest.ID)
		}
	}
}
