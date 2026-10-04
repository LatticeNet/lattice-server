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
	r.processExitFor("latticenet.example")(cmd.ProcessState)
	if len(got) != 1 || got[0].pluginID != "latticenet.example" {
		t.Fatalf("observed %+v", got)
	}
	if got[0].cpu <= 0 || got[0].rss < 1<<20 {
		t.Fatalf("a Go test binary used %v CPU and peaked at %d bytes; want both measured", got[0].cpu, got[0].rss)
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
	worker, err := startSystemWorkerObserved(t.Context(), os.Args[0], dir, env, func(st *os.ProcessState) {
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
