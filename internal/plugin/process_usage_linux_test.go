//go:build linux

package plugin

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestParseVmHWM(t *testing.T) {
	status := []byte("Name:\tartifact\nVmPeak:\t 1471684 kB\nVmHWM:\t  150600 kB\nVmRSS:\t   66252 kB\n")
	if got := parseVmHWM(status); got != 150600*1024 {
		t.Fatalf("VmHWM %d", got)
	}
	// A zombie's status has no Vm lines; a malformed one reads as nothing.
	for _, bad := range []string{"Name:\tz\nState:\tZ (zombie)\n", "VmHWM:\t12 MB\n", "VmHWM:\t-1 kB\n", "VmHWM:\n", ""} {
		if got := parseVmHWM([]byte(bad)); got != 0 {
			t.Fatalf("%q read as %d", bad, got)
		}
	}
	if got := readVmHWMBytes(os.Getpid()); got < 1<<20 {
		t.Fatalf("this test process reads VmHWM %d", got)
	}
}

// A plugin process must report its own peak. Its exit rusage carries the
// high-water mark of the address space exec replaced, which for a Go parent is
// lattice-server's own, so the parent grows here first, the way the server's
// mapped store makes it large in production.
func TestPooledWorkerPeakIsItsOwnNotTheServers(t *testing.T) {
	const ballast = 256 << 20
	b := make([]byte, ballast)
	for i := 0; i < len(b); i += 4096 {
		b[i] = 1
	}
	defer runtime.KeepAlive(b)

	dir := filepath.Join(t.TempDir(), "w")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	type exit struct {
		state *os.ProcessState
		peak  int64
	}
	exited := make(chan exit, 1)
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
	worker, err := startSystemWorkerObserved(t.Context(), os.Args[0], dir, env, func(st *os.ProcessState, peak int64) {
		exited <- exit{st, peak}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.awaitReadyContext(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	_ = worker.abort()
	var got exit
	select {
	case got = <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("worker was not reaped")
	}
	inherited := int64(0)
	if ru, ok := got.state.SysUsage().(*syscall.Rusage); ok {
		inherited = rusageMaxRSSBytes(ru)
	}
	t.Logf("worker: sampled peak %d bytes, exit rusage %d bytes", got.peak, inherited)
	// The mechanism this test is about: without it the check below proves
	// nothing, so a kernel that stops carrying the mark fails here loudly.
	if inherited < ballast {
		t.Fatalf("exit rusage %d is under the parent's %d ballast; the kernel no longer carries the parent's high-water mark", inherited, ballast)
	}
	if got.peak <= 0 || got.peak >= ballast/2 {
		t.Fatalf("sampled peak %d; want the worker's own, under %d", got.peak, ballast/2)
	}
}

// A per-invocation process usually answers and exits within a second, so its
// peak comes from the dense early samples. This one holds about 64 MiB for
// over a second before it answers, so a busy host still samples it, inside a
// parent grown past that.
func TestSystemRunnerInvocationPeakIsItsOwn(t *testing.T) {
	const ballast = 256 << 20
	b := make([]byte, ballast)
	for i := 0; i < len(b); i += 4096 {
		b[i] = 1
	}
	defer runtime.KeepAlive(b)

	rec := newExitRecorder()
	r := newRunner(t, SystemRunnerOptions{ProcessObserver: rec.observe})
	script := "#!/bin/sh\nread line\nx=$(head -c 67108864 /dev/zero | tr '\\0' a)\nsleep 1.2\necho '{\"ok\":true}'\n"
	loaded := makeBundle(t, "p.peak", script, "")
	resp, err := startInvoke(t, r, loaded, "plan", nil)
	if err != nil || !resp.OK {
		t.Fatalf("Invoke = %+v, %v", resp, err)
	}
	got := rec.wait(t, 1)
	if len(got) != 1 {
		t.Fatalf("observed %+v", got)
	}
	t.Logf("invocation: sampled peak %d bytes", got[0].rss)
	if got[0].rss < 48<<20 || got[0].rss >= ballast {
		t.Fatalf("sampled peak %d; want the process's own 64 MiB string, at least %d and under the parent's %d", got[0].rss, 48<<20, ballast)
	}
}

func TestProcessPeakFinishStopsTheSampler(t *testing.T) {
	p := watchProcessPeak(os.Getpid())
	if p.max.Load() < 1<<20 {
		t.Fatalf("first look read %d", p.max.Load())
	}
	first := p.finish()
	if again := p.finish(); again != first {
		t.Fatalf("finish twice: %d then %d", first, again)
	}
	select {
	case <-p.stopped:
	default:
		t.Fatal("finish returned with the sampler still running")
	}
	// After finish a sample reads nothing: a reaped pid may belong to
	// another process by then.
	p.max.Store(1)
	p.sample()
	if got := p.max.Load(); got != 1 {
		t.Fatalf("a sample after finish moved the peak to %d", got)
	}
}
