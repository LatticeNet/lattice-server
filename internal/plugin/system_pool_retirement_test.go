package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const retirementTestPluginID = "p.test"

func TestSystemRunnerPoolRetiresPostResultReadyFailures(t *testing.T) {
	cases := []struct {
		name      string
		flag      string
		resultKey string
	}{
		{name: "NO_READY", flag: "LATTICE_TEST_V2_NO_READY=1", resultKey: "once"},
		{name: "MALFORMED_READY", flag: "LATTICE_TEST_V2_MALFORMED_READY=1", resultKey: "helper"},
		{name: "BAD_READY", flag: "LATTICE_TEST_V2_BAD_READY=1", resultKey: "helper"},
		{name: "WRONG_INVOCATION_READY", flag: "LATTICE_TEST_V2_WRONG_INVOCATION_READY=1", resultKey: "helper"},
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

			spawnGood := readyTestSpawner(t)
			pool.replenishFn = func(ctx context.Context, generation uint64) (*pooledWorker, error) {
				good, err := spawnGood(ctx)
				if err != nil {
					return nil, err
				}
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
			if !first.OK {
				t.Fatalf("first response did not preserve terminal result and warning: %+v", first)
			}
			if len(first.Warnings) != 1 || first.Warnings[0] != "persistent worker retired after terminal protocol failure" {
				t.Fatalf("first warnings=%q, want deterministic retirement warning", first.Warnings)
			}
			if got := resultPID(t, first.Result); got != badPID {
				t.Fatalf("first result pid=%d, want retired pid=%d", got, badPID)
			}
			wantResult := json.RawMessage(`{"` + tc.resultKey + `":true,"pid":` + fmt.Sprint(badPID) + `}`)
			if !jsonEqual(first.Result, wantResult) {
				t.Fatalf("first result=%s, want exact business payload %s", first.Result, wantResult)
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

func TestSystemRunnerV2PreservesCanonicalResponseSemantics(t *testing.T) {
	cases := []struct {
		name        string
		flags       []string
		wantOK      bool
		wantMessage string
		wantResult  string
		wantWarning []string
		wantErr     bool
	}{
		{name: "error ready", flags: []string{"LATTICE_TEST_V2_ERROR_RESPONSE=1"}, wantMessage: "helper denied", wantWarning: []string{"plugin warning"}, wantErr: true},
		{name: "error retirement", flags: []string{"LATTICE_TEST_V2_ERROR_RESPONSE=1", "LATTICE_TEST_V2_NO_READY_AFTER_RESULT=1"}, wantMessage: "helper denied", wantWarning: []string{"plugin warning", "persistent worker retired after terminal protocol failure"}, wantErr: true},
		{name: "success warning retirement", flags: []string{"LATTICE_TEST_V2_WARN_RESPONSE=1", "LATTICE_TEST_V2_NO_READY_AFTER_RESULT=1"}, wantOK: true, wantWarning: []string{"plugin warning", "persistent worker retired after terminal protocol failure"}},
		{name: "message only", flags: []string{"LATTICE_TEST_V2_MESSAGE_RESPONSE=1"}, wantOK: true, wantMessage: "done"},
		{name: "plan only", flags: []string{"LATTICE_TEST_V2_PLAN_RESPONSE=1"}, wantOK: true, wantResult: `"plan text"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			worker := startReadyTestWorker(t, tc.flags...)
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, worker, time.Now()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pool.drain(1) })
			rsp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "response"})
			if (err != nil) != tc.wantErr || rsp.OK != tc.wantOK || rsp.Message != tc.wantMessage || (tc.wantResult != "" && string(rsp.Result) != tc.wantResult) || !reflect.DeepEqual(rsp.Warnings, tc.wantWarning) {
				t.Fatalf("response=%+v err=%v", rsp, err)
			}
		})
	}
}

func TestSystemRunnerV2CircuitTracksTransportHealth(t *testing.T) {
	t.Run("ready retirement opens circuit", func(t *testing.T) {
		pool := newSystemPool(256, time.Hour, 1)
		spawnBad := readyTestSpawner(t, "LATTICE_TEST_V2_BAD_READY=1")
		var starts atomic.Int64
		pool.replenishFn = func(ctx context.Context, generation uint64) (*pooledWorker, error) {
			starts.Add(1)
			tr, err := spawnBad(ctx)
			if err != nil {
				return nil, err
			}
			return &pooledWorker{state: workerIdle, generation: generation, started: time.Now(), transport: tr}, nil
		}
		first, err := pool.replenishFn(t.Context(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := pool.publishTransport(1, first.transport, time.Now()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pool.drain(1) })
		runner := runnerWithPool(pool, nil)
		for i := 0; i < defaultCrashThreshold; i++ {
			if rsp, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "retire"}); err != nil || !rsp.OK {
				t.Fatalf("retirement %d response=%+v err=%v", i, rsp, err)
			}
		}
		if _, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "blocked"}); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("circuit error=%v, want ErrCircuitOpen", err)
		}
		if got := starts.Load(); got != int64(defaultCrashThreshold) {
			t.Fatalf("worker starts=%d, want %d with zero post-threshold spawn", got, defaultCrashThreshold)
		}
	})

	t.Run("reusable business failures keep circuit closed", func(t *testing.T) {
		tr := startReadyTestWorker(t, "LATTICE_TEST_V2_ERROR_RESPONSE=1")
		pid := tr.pgid
		pool := newSystemPool(256, time.Hour, 1)
		if err := pool.publishTransport(1, tr, time.Now()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pool.drain(1) })
		runner := runnerWithPool(pool, nil)
		for i := 0; i < defaultCrashThreshold+1; i++ {
			rsp, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "deny"})
			if err == nil || rsp.OK || rsp.Message != "helper denied" {
				t.Fatalf("business failure %d response=%+v err=%v", i, rsp, err)
			}
		}
		if err := syscall.Kill(-pid, 0); err != nil {
			t.Fatalf("reusable worker was retired: %v", err)
		}
	})
}

func TestSystemPoolCircuitOpenRevokesQueuedAndReleasedWorkers(t *testing.T) {
	p := newSystemPool(256, time.Hour, 1)
	a, b := startReadyTestWorker(t), startReadyTestWorker(t)
	for _, tr := range []*systemWorkerTransport{a, b} {
		if err := p.publishTransport(1, tr, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	one, err := p.checkout(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	two, err := p.checkout(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	queued := make(chan error, 1)
	go func() { _, err := p.checkout(t.Context(), time.Now()); queued <- err }()
	for {
		p.mu.Lock()
		n := len(p.waiters)
		p.mu.Unlock()
		if n == 1 {
			break
		}
		runtime.Gosched()
	}
	p.setCircuitOpen(true)
	if err := <-queued; !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("queued checkout error=%v", err)
	}
	p.release(one, true, time.Now())
	p.release(two, true, time.Now())
	assertProcessGroupGone(t, a.pgid)
	assertProcessGroupGone(t, b.pgid)
	p.abortClose(1)
}

func TestSystemPoolDrainCancelsAndJoinsSupervisor(t *testing.T) {
	p := newSystemPool(256, time.Hour, 1)
	entered, exited := make(chan struct{}), make(chan struct{})
	p.replenishFn = func(ctx context.Context, _ uint64) (*pooledWorker, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	}
	checkout := make(chan error, 1)
	go func() { _, err := p.checkout(t.Context(), time.Now()); checkout <- err }()
	<-entered
	p.abortClose(1)
	<-exited
	if err := <-checkout; !errors.Is(err, errSystemPoolClosed) {
		t.Fatalf("checkout error=%v", err)
	}
	p.mu.Lock()
	starting := p.starting
	p.mu.Unlock()
	if starting != 0 {
		t.Fatalf("starting=%d after supervisor join", starting)
	}
}

func TestSystemPoolGracefulDrainClosesAfterLeasedPoison(t *testing.T) {
	p := newSystemPool(256, time.Hour, 1)
	tr := startReadyTestWorker(t)
	if err := p.publishTransport(1, tr, time.Now()); err != nil {
		t.Fatal(err)
	}
	w, err := p.checkout(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	drained := p.gracefulDrain(1)
	p.poison(w)
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not close after leased poison")
	}
	assertProcessGroupGone(t, tr.pgid)
}

func TestSystemPoolPrunesInvalidIdleBeforeWake(t *testing.T) {
	for _, mode := range []string{"max-age", "max-use", "stale-generation"} {
		t.Run(mode, func(t *testing.T) {
			p := newSystemPool(2, time.Hour, 1)
			old := startReadyTestWorker(t)
			if err := p.publishTransport(1, old, time.Now()); err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			switch mode {
			case "max-age":
				p.workers[0].started = time.Now().Add(-2 * p.maxAge)
			case "max-use":
				p.workers[0].uses = p.maxUses
			case "stale-generation":
				p.workers[0].generation--
			}
			p.mu.Unlock()
			spawn := readyTestSpawner(t)
			p.replenishFn = func(ctx context.Context, generation uint64) (*pooledWorker, error) {
				tr, err := spawn(ctx)
				return &pooledWorker{generation: generation, started: time.Now(), transport: tr}, err
			}
			w, err := p.checkout(t.Context(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if w.transport == old {
				t.Fatal("invalid idle worker was leased")
			}
			assertProcessGroupGone(t, old.pgid)
			p.release(w, true, time.Now())
			p.abortClose(1)
		})
	}
}

func TestSystemRunnerPostResultRetirementDoesNotWaitForReplenishment(t *testing.T) {
	bad := startReadyTestWorker(t, "LATTICE_TEST_V2_NO_READY=1")
	pool := newSystemPool(256, time.Hour, 1)
	if err := pool.publishTransport(1, bad, time.Now()); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	gate := make(chan struct{})
	pool.replenishFn = func(ctx context.Context, _ uint64) (*pooledWorker, error) {
		close(entered)
		select {
		case <-gate:
			return nil, errors.New("blocked replacement failed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	t.Cleanup(func() { close(gate); pool.drain(1) })
	done := make(chan struct {
		rsp InvokeResponse
		err error
	}, 1)
	go func() {
		rsp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "retire"})
		done <- struct {
			rsp InvokeResponse
			err error
		}{rsp, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("replenishment did not start")
	}
	select {
	case got := <-done:
		if got.err != nil || !got.rsp.OK || len(got.rsp.Warnings) != 1 {
			t.Fatalf("terminal result blocked or changed: response=%+v err=%v", got.rsp, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal result waited for replacement startup")
	}
}

func TestSystemRunnerV2EnforcesCumulativeStdoutBudget(t *testing.T) {
	tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_HOST_CALLS=3")
	pool := newSystemPool(256, time.Hour, 1)
	if err := pool.publishTransport(1, tr, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.drain(1) })
	broker := newTestBroker(t, retirementTestPluginID, []string{"log:write"}, HostServices{Log: noopTestLog{}})
	runner := runnerWithPool(pool, broker)
	_, err := runner.Invoke(t.Context(), InvokeRequest{
		PluginID:    retirementTestPluginID,
		Generation:  1,
		Action:      "cumulative",
		Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 300, StderrBytes: 1024, HostCalls: 10}},
	})
	if err == nil || !strings.Contains(err.Error(), "stdout limit 300") {
		t.Fatalf("cumulative stdout error=%v", err)
	}
	assertProcessGroupGone(t, tr.pgid)
}

func TestSystemRunnerV2ChargesFramedDiagnosticsToSignedBudget(t *testing.T) {
	tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_STDERR="+strings.Repeat("d", 65))
	pool := newSystemPool(256, time.Hour, 1)
	if err := pool.publishTransport(1, tr, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.drain(1) })
	resp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{
		PluginID: retirementTestPluginID, Generation: 1, Action: "diagnostics",
		Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 1 << 20, StderrBytes: 64, HostCalls: 0}},
	})
	if err != nil || !resp.OK || len(resp.Warnings) != 1 || resp.Warnings[0] != "stderr truncated after 64 bytes" {
		t.Fatalf("response=%+v err=%v", resp, err)
	}
}

func TestSystemRunnerV2FramedDiagnosticsDoNotConsumeStdoutBudget(t *testing.T) {
	tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_STDERR="+strings.Repeat("d", 64<<10))
	pool := newSystemPool(256, time.Hour, 1)
	if err := pool.publishTransport(1, tr, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.drain(1) })
	resp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{
		PluginID: retirementTestPluginID, Generation: 1, Action: "diagnostics-large",
		Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 1 << 10, StderrBytes: 64 << 10, HostCalls: 0}},
	})
	if err != nil || !resp.OK || len(resp.Warnings) != 0 {
		t.Fatalf("response=%+v err=%v", resp, err)
	}
}

func TestSystemRunnerV2RawStderrIsProcessTelemetryOnly(t *testing.T) {
	tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_RAW_STDERR="+strings.Repeat("secret", 16<<10))
	pool := newSystemPool(256, time.Hour, 1)
	if err := pool.publishTransport(1, tr, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.drain(1) })
	runner := runnerWithPool(pool, nil)
	for i := 0; i < 2; i++ {
		resp, err := runner.Invoke(t.Context(), InvokeRequest{
			PluginID: retirementTestPluginID, Generation: 1, Action: "raw-stderr",
			Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 1 << 20, StderrBytes: 64, HostCalls: 0}},
		})
		if err != nil || !resp.OK || len(resp.Warnings) != 0 {
			t.Fatalf("invoke %d response=%+v err=%v", i, resp, err)
		}
	}
	pool.abortClose(1)
	if got, want := tr.rawStderrBytes.Load(), int64(2*len(strings.Repeat("secret", 16<<10))); got != want {
		t.Fatalf("bounded raw stderr counter=%d want=%d", got, want)
	}
}

func TestSystemRunnerV2RejectsUnboundedDiagnosticFrames(t *testing.T) {
	for _, env := range []string{"LATTICE_TEST_V2_STDERR_OVERSIZE=1", "LATTICE_TEST_V2_STDERR_TINY_FLOOD=1"} {
		t.Run(env, func(t *testing.T) {
			tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", env)
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			runner := runnerWithPool(pool, nil)
			_, err := runner.Invoke(t.Context(), InvokeRequest{
				PluginID: retirementTestPluginID, Generation: 1, Action: "diagnostic-hostile",
				Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 1 << 20, StderrBytes: HostMaxInvokeStderrBytes, HostCalls: 0}},
			})
			if err == nil {
				t.Fatal("unbounded diagnostic frames were accepted")
			}
			assertProcessGroupGone(t, tr.pgid)
			pool.abortClose(1)
		})
	}
}

func TestSystemRunnerV2EnforcesCumulativeDecodedDiagnosticCeiling(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		wantOK bool
	}{{mode: "exact", wantOK: true}, {mode: "over"}} {
		t.Run(tc.mode, func(t *testing.T) {
			tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_STDERR_MULTI="+tc.mode)
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			resp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{
				PluginID: retirementTestPluginID, Generation: 1, Action: tc.mode,
				Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 1 << 20, StderrBytes: HostMaxInvokeStderrBytes, HostCalls: 0}},
			})
			if tc.wantOK {
				if err != nil || !resp.OK || len(resp.Warnings) != 0 {
					t.Fatalf("response=%+v err=%v", resp, err)
				}
				pool.abortClose(1)
			} else {
				if err == nil || !strings.Contains(err.Error(), "diagnostic decoded limit") {
					t.Fatalf("response=%+v err=%v", resp, err)
				}
				assertProcessGroupGone(t, tr.pgid)
				pool.abortClose(1)
			}
		})
	}
}

func TestSystemRunnerV2EnforcesSingleDiagnosticChunkBoundary(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		wantOK bool
	}{{mode: "exact", wantOK: true}, {mode: "over"}} {
		t.Run(tc.mode, func(t *testing.T) {
			tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_STDERR_SINGLE="+tc.mode)
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			resp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: tc.mode})
			if tc.wantOK {
				if err != nil || !resp.OK {
					t.Fatalf("response=%+v err=%v", resp, err)
				}
			} else if err == nil {
				t.Fatalf("response=%+v err=%v", resp, err)
			}
			pool.abortClose(1)
		})
	}
}

func TestSystemRunnerV2EnforcesFramedDiagnosticOrdering(t *testing.T) {
	for _, mode := range []string{"late_chunk", "duplicate_complete", "mismatch_complete"} {
		t.Run(mode, func(t *testing.T) {
			tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_STDERR_ORDER="+mode)
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			resp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: mode})
			if err != nil || !resp.OK || !jsonEqual(resp.Result, json.RawMessage(`{"helper":true,"pid":`+strconv.Itoa(tr.pgid)+`}`)) || !slices.Contains(resp.Warnings, "persistent worker retired after terminal protocol failure") {
				t.Fatalf("response=%+v err=%v", resp, err)
			}
			assertProcessGroupGone(t, tr.pgid)
			pool.abortClose(1)
		})
	}
	t.Run("complete_before_result", func(t *testing.T) {
		tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_STDERR_ORDER=complete_before_result")
		pool := newSystemPool(256, time.Hour, 1)
		if err := pool.publishTransport(1, tr, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: "complete-before-result"}); err == nil {
			t.Fatal("stderr_complete before result was accepted")
		}
		assertProcessGroupGone(t, tr.pgid)
		pool.abortClose(1)
	})
}

func TestSystemRunnerV2RejectsHostileFramesOnProductionPath(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "unknown", "null", "trailing", "correlation", "nested_params_duplicate", "nested_result_duplicate", "nested_warnings_duplicate"} {
		t.Run(mode, func(t *testing.T) {
			tr := startReadyTestWorker(t, "LATTICE_TEST_V2_HOSTILE_FRAME="+mode)
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pool.drain(1) })
			if _, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Action: mode}); err == nil {
				t.Fatal("hostile frame reached a successful result")
			}
			assertProcessGroupGone(t, tr.pgid)
		})
	}
}

func TestSystemRunnerV2RejectsDuplicateHostCallIDAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flags  []string
		budget int
		want   string
	}{
		{name: "duplicate id", flags: []string{"LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_HOST_CALLS=2", "LATTICE_TEST_V2_DUPLICATE_HOST_CALL_ID=1"}, budget: 2, want: "duplicate host_call_id"},
		{name: "host call budget", flags: []string{"LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_HOST_CALLS=2"}, budget: 1, want: "host-call limit 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := startReadyTestWorker(t, tc.flags...)
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pool.drain(1) })
			broker := newTestBroker(t, retirementTestPluginID, []string{"log:write"}, HostServices{Log: noopTestLog{}})
			_, err := runnerWithPool(pool, broker).Invoke(t.Context(), InvokeRequest{
				PluginID:    retirementTestPluginID,
				Generation:  1,
				Action:      tc.name,
				Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 1 << 20, StderrBytes: 1024, HostCalls: tc.budget}},
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
			assertProcessGroupGone(t, tr.pgid)
		})
	}
}

func TestSystemRunnerV2ScannerSupportsAuthorizedLargeFrame(t *testing.T) {
	const payloadBytes = 5 << 20
	for _, tc := range []struct {
		name   string
		budget int
		wantOK bool
	}{
		{name: "authorized above old scanner ceiling", budget: 6 << 20, wantOK: true},
		{name: "signed lower limit", budget: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := startReadyTestWorker(t, "LATTICE_TEST_V2_RESULT_BYTES="+strconv.Itoa(payloadBytes))
			pool := newSystemPool(256, time.Hour, 1)
			if err := pool.publishTransport(1, tr, time.Now()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pool.drain(1) })
			rsp, err := runnerWithPool(pool, nil).Invoke(t.Context(), InvokeRequest{
				PluginID:    retirementTestPluginID,
				Generation:  1,
				Action:      "large",
				Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 10_000, StdoutBytes: tc.budget, StderrBytes: 1024, HostCalls: 0}},
			})
			if tc.wantOK {
				if err != nil || !rsp.OK || len(rsp.Result) < payloadBytes {
					t.Fatalf("large authorized response bytes=%d err=%v", len(rsp.Result), err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "stdout limit") {
				t.Fatalf("lower signed budget response=%+v err=%v", rsp, err)
			}
		})
	}
}

func jsonEqual(got, want json.RawMessage) bool {
	var gotValue, wantValue any
	return json.Unmarshal(got, &gotValue) == nil &&
		json.Unmarshal(want, &wantValue) == nil &&
		reflect.DeepEqual(gotValue, wantValue)
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

func TestSystemRunnerCallerCancellationDoesNotOpenCircuit(t *testing.T) {
	pool := newSystemPool(256, time.Hour, 1)
	spawn := readyTestSpawner(t, "LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_STALL=1")
	pool.replenishFn = func(ctx context.Context, generation uint64) (*pooledWorker, error) {
		tr, err := spawn(ctx)
		if err != nil {
			return nil, err
		}
		return &pooledWorker{generation: generation, started: time.Now(), transport: tr}, nil
	}
	first, err := pool.replenishFn(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.publishTransport(1, first.transport, time.Now()); err != nil {
		t.Fatal(err)
	}
	cancels := make(chan context.CancelFunc, defaultCrashThreshold+1)
	broker := newTestBroker(t, retirementTestPluginID, []string{"log:write"}, HostServices{Log: cancelQueueLog{cancels: cancels}})
	runner := runnerWithPool(pool, broker)
	for i := 0; i < defaultCrashThreshold+1; i++ {
		ctx, cancel := context.WithCancel(t.Context())
		cancels <- cancel
		if _, err := runner.Invoke(ctx, InvokeRequest{PluginID: retirementTestPluginID, Generation: 1}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel %d err=%v", i, err)
		}
	}
	runner.mu.Lock()
	tripped := runner.st[retirementTestPluginID][1].tripped
	runner.mu.Unlock()
	if tripped {
		t.Fatal("caller cancellations opened circuit")
	}
	pool.abortClose(1)
}

type cancelQueueLog struct{ cancels <-chan context.CancelFunc }

func (l cancelQueueLog) Write(context.Context, HostLogEntry) error {
	(<-l.cancels)()
	return nil
}

func TestSystemRunnerSignedTimeoutsOpenCircuit(t *testing.T) {
	pool := newSystemPool(256, time.Hour, 1)
	spawn := readyTestSpawner(t, "LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_STALL=1")
	pool.replenishFn = func(ctx context.Context, generation uint64) (*pooledWorker, error) {
		tr, err := spawn(ctx)
		if err != nil {
			return nil, err
		}
		return &pooledWorker{generation: generation, started: time.Now(), transport: tr}, nil
	}
	first, err := pool.replenishFn(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.publishTransport(1, first.transport, time.Now()); err != nil {
		t.Fatal(err)
	}
	dispatched := make(chan struct{}, defaultCrashThreshold)
	broker := newTestBroker(t, retirementTestPluginID, []string{"log:write"}, HostServices{Log: dispatchQueueLog{dispatched: dispatched}})
	runner := runnerWithPool(pool, broker)
	replenished := make(chan struct{}, defaultCrashThreshold)
	pool.successFn = func(generation uint64) {
		runner.recordGenerationSuccess(retirementTestPluginID, generation)
		replenished <- struct{}{}
	}
	for i := 0; i < defaultCrashThreshold; i++ {
		done := make(chan error, 1)
		go func() {
			_, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1, Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 200, StdoutBytes: 1024, StderrBytes: 1024, HostCalls: 1}}})
			done <- err
		}()
		select {
		case <-dispatched:
		case <-time.After(5 * time.Second):
			t.Fatalf("attempt %d never dispatched", i)
		}
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("attempt %d error=%v", i, err)
		}
		if i < defaultCrashThreshold-1 {
			select {
			case <-replenished:
			case <-time.After(5 * time.Second):
				t.Fatalf("attempt %d replacement not ready", i)
			}
		}
	}
	if _, err := runner.Invoke(t.Context(), InvokeRequest{PluginID: retirementTestPluginID, Generation: 1}); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("circuit error=%v", err)
	}
	pool.abortClose(1)
}

type dispatchQueueLog struct{ dispatched chan<- struct{} }

func (l dispatchQueueLog) Write(context.Context, HostLogEntry) error {
	l.dispatched <- struct{}{}
	return nil
}

type cancelOnLog struct {
	seen   chan struct{}
	cancel context.CancelFunc
}

type noopTestLog struct{}

func (noopTestLog) Write(context.Context, HostLogEntry) error { return nil }

func (l cancelOnLog) Write(context.Context, HostLogEntry) error {
	close(l.seen)
	l.cancel()
	return nil
}

func startReadyTestWorker(t *testing.T, flags ...string) *systemWorkerTransport {
	t.Helper()
	spawn := readyTestSpawner(t, flags...)
	worker, err := spawn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func readyTestSpawner(t *testing.T, flags ...string) func(context.Context) (*systemWorkerTransport, error) {
	t.Helper()
	root := t.TempDir()
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
	env = append(env, flags...)
	var sequence atomic.Uint64
	return func(ctx context.Context) (*systemWorkerTransport, error) {
		dir := filepath.Join(root, strconv.FormatUint(sequence.Add(1), 10))
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
		worker, err := startSystemWorker(ctx, os.Args[0], dir, env)
		if err != nil {
			return nil, err
		}
		if err := worker.awaitReadyContext(ctx, 1); err != nil {
			_ = worker.abort()
			return nil, err
		}
		return worker, nil
	}
}

func runnerWithPool(pool *systemPool, broker *Broker) *SystemRunner {
	runner := NewSystemRunner(SystemRunnerOptions{})
	runner.st[retirementTestPluginID] = map[uint64]*systemPluginState{
		pool.generation: {pool: pool, isV2: true, broker: broker, generation: pool.generation, admitted: true},
	}
	pool.failureFn = func(generation uint64) { runner.recordGenerationFailure(retirementTestPluginID, generation) }
	pool.successFn = func(generation uint64) { runner.recordGenerationSuccess(retirementTestPluginID, generation) }
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
