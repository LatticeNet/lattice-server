package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

const retirementTestPluginID = "p.test"

func TestSystemRunnerPoolRetiresPostResultReadyFailures(t *testing.T) {
	cases := []struct {
		name string
		flag string
	}{
		{name: "NO_READY", flag: "LATTICE_TEST_V2_NO_READY=1"},
		{name: "MALFORMED_READY", flag: "LATTICE_TEST_V2_MALFORMED_READY=1"},
		{name: "BAD_READY", flag: "LATTICE_TEST_V2_BAD_READY=1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := startReadyTestWorker(t, tc.flag)
			badPID := bad.pgid
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, bad, time.Now()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pool.drain(1) })

			pool.replenishFn = func(generation uint64) (*pooledWorker, error) {
				good := startReadyTestWorker(t)
				return &pooledWorker{
					state:      workerIdle,
					generation: generation,
					started:    time.Now(),
					transport:  good,
				}, nil
			}
			runner := runnerWithPool(pool, nil)

			first, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "first"})
			if err != nil {
				t.Fatalf("first Invoke: %v", err)
			}
			if !first.OK || len(first.Warnings) == 0 {
				t.Fatalf("first response did not preserve terminal result and warning: %+v", first)
			}
			if got := resultPID(t, first.Result); got != badPID {
				t.Fatalf("first result pid=%d, want retired pid=%d", got, badPID)
			}
			assertProcessGroupGone(t, badPID)

			second, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "second"})
			if err != nil {
				t.Fatalf("second Invoke: %v", err)
			}
			secondPID := resultPID(t, second.Result)
			if !second.OK || secondPID == badPID {
				t.Fatalf("replacement was not used: response=%+v old_pid=%d", second, badPID)
			}
		})
	}
}

func TestSystemRunnerPoolCancellationAtObservedHostCallReaps(t *testing.T) {
	bad := startReadyTestWorker(t, "LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_STALL=1")
	badPID := bad.pgid
	pool := newSystemPool(256, time.Hour, 1)
	if err := pool.publishTransport(1, bad, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.drain(1) })

	ctx, cancel := context.WithCancel(t.Context())
	seen := make(chan struct{})
	broker := newTestBroker(t, retirementTestPluginID, []string{"log:write"}, HostServices{
		Log: cancelOnLog{seen: seen, cancel: cancel},
	})
	runner := runnerWithPool(pool, broker)
	done := make(chan error, 1)
	go func() {
		_, err := runner.Invoke(ctx, InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "stall"})
		done <- err
	}()

	select {
	case <-seen:
		// The real host callback canceled the invocation synchronously.
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("helper never reached the host callback")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Invoke error=%v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("Invoke did not return after callback cancellation")
	}
	assertProcessGroupGone(t, badPID)
}

type cancelOnLog struct {
	seen   chan struct{}
	cancel context.CancelFunc
}

func (l cancelOnLog) Write(context.Context, HostLogEntry) error {
	close(l.seen)
	l.cancel()
	return nil
}

func startReadyTestWorker(t *testing.T, flags ...string) *systemWorkerTransport {
	t.Helper()
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
	env = append(env, flags...)
	worker, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.awaitReady(1); err != nil {
		_ = worker.abort()
		t.Fatal(err)
	}
	return worker
}

func runnerWithPool(pool *systemPool, broker *Broker) *SystemRunner {
	runner := NewSystemRunner(SystemRunnerOptions{})
	runner.st[retirementTestPluginID] = &systemPluginState{pool: pool, isV2: true, broker: broker}
	return runner
}

func resultPID(t *testing.T, raw json.RawMessage) int {
	t.Helper()
	var result struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode result %s: %v", raw, err)
	}
	if result.PID <= 0 {
		t.Fatalf("result has invalid pid: %s", raw)
	}
	return result.PID
}

func assertProcessGroupGone(t *testing.T, pgid int) {
	t.Helper()
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process group %d still alive: %v", pgid, err)
	}
}
