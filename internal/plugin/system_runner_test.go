package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
)

// makeBundle writes a bundle dir containing a manifest.json and an artifact shell
// script (readable; the runner stages an executable 0700 copy), returning a
// Loaded for the system runner. digest is optional; if set it is recorded on the
// manifest so Start re-verifies it.
func makeBundle(t *testing.T, id, script, digest string) Loaded {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, manifestFileName), []byte(`{"id":"`+id+`","name":"x","type":"system","capabilities":["task:run"]}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, artifactFileName), []byte(script), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	return Loaded{
		Manifest:     Manifest{ID: id, Name: "x", Type: TypeSystem, Capabilities: []string{"task:run"}, DigestSHA256: digest},
		Capabilities: []string{"task:run"},
		BundlePath:   dir,
	}
}

func newRunner(t *testing.T, opts SystemRunnerOptions) *SystemRunner {
	t.Helper()
	if opts.RuntimeDir == "" {
		opts.RuntimeDir = t.TempDir()
	}
	return NewSystemRunner(opts)
}

func startInvoke(t *testing.T, r *SystemRunner, loaded Loaded, action string, payload json.RawMessage) (InvokeResponse, error) {
	t.Helper()
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Action: action, Payload: payload})
}

func TestSystemRunnerHappyPath(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	loaded := makeBundle(t, "p.happy", "#!/bin/sh\nread line\necho '{\"ok\":true,\"message\":\"hi\",\"result\":{\"v\":1}}'\n", "")
	resp, err := startInvoke(t, r, loaded, "plan", nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if !resp.OK || resp.Message != "hi" || string(resp.Result) != `{"v":1}` {
		t.Fatalf("unexpected response: %+v result=%s", resp, resp.Result)
	}
}

func TestSystemInvocationLeaseRejectsCanceledCallerBeforeDispatch(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "started")
	loaded := makeBundle(t, "p.cancel-before-dispatch", "#!/bin/sh\ntouch "+canary+"\n", "")
	r := newRunner(t, SystemRunnerOptions{})
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	if err := r.ActivateGeneration(loaded.Manifest.ID, 1); err != nil {
		t.Fatal(err)
	}
	lease, err := r.AcquireInvocation(loaded.Manifest.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lease.Invoke(ctx, InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Invoke error=%v want context.Canceled", err)
	}
	lease.Release()
	if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled invocation dispatched: stat err=%v", err)
	}
}

func TestSystemRunnerStopCancelsAcquiredV1BeforeDispatch(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "started")
	loaded := makeBundle(t, "p.stop-before-dispatch", "#!/bin/sh\ntouch "+canary+"\n", "")
	r := newRunner(t, SystemRunnerOptions{})
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	if err := r.ActivateGeneration(loaded.Manifest.ID, 1); err != nil {
		t.Fatal(err)
	}
	lease, err := r.AcquireInvocation(loaded.Manifest.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- r.Stop(t.Context(), RunnerStopRequest{PluginID: loaded.Manifest.ID, Generation: 1})
	}()
	systemLease := lease.(*systemInvocationLease)
	select {
	case <-systemLease.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("generation root was not canceled")
	}
	if _, err := lease.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Invoke error=%v want context.Canceled", err)
	}
	lease.Release()
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stopped invocation dispatched: stat err=%v", err)
	}
}

type leaseContextKey struct{}

type contextObservingLog struct {
	value    any
	deadline bool
}

func (l *contextObservingLog) Write(ctx context.Context, _ HostLogEntry) error {
	l.value = ctx.Value(leaseContextKey{})
	_, l.deadline = ctx.Deadline()
	return nil
}

func TestSystemInvocationLeasePreservesCallerValuesAndDeadline(t *testing.T) {
	loaded := makeBundle(t, "p.lease-context", "#!/bin/sh\nread line\necho '{\"host_call\":{\"id\":\"h1\",\"method\":\"log.write\",\"params\":{\"level\":\"info\",\"message\":\"seen\"}}}'\nread response <&3\necho '{\"ok\":true}'\n", "")
	observer := &contextObservingLog{}
	broker := newTestBroker(t, loaded.Manifest.ID, []string{"log:write"}, HostServices{Log: observer})
	r := newRunner(t, SystemRunnerOptions{})
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded, Broker: broker}); err != nil {
		t.Fatal(err)
	}
	if err := r.ActivateGeneration(loaded.Manifest.ID, 1); err != nil {
		t.Fatal(err)
	}
	lease, err := r.AcquireInvocation(loaded.Manifest.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx := context.WithValue(context.Background(), leaseContextKey{}, "bound")
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := lease.Invoke(ctx, InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if observer.value != "bound" || !observer.deadline {
		t.Fatalf("caller context lost: value=%v deadline=%v", observer.value, observer.deadline)
	}
}

func TestSystemRunnerStopWaitsForActiveV1ProcessReap(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	loaded := makeBundle(t, "p.stop-active-v1", "#!/bin/sh\nread line\necho $$ > '"+pidFile+"'\nsleep 30\n", "")
	r := newRunner(t, SystemRunnerOptions{StopGrace: 10 * time.Millisecond})
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	if err := r.ActivateGeneration(loaded.Manifest.ID, 1); err != nil {
		t.Fatal(err)
	}
	invokeDone := make(chan error, 1)
	go func() {
		_, err := r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Action: "block"})
		invokeDone <- err
	}()
	var pid int
	deadline := time.After(5 * time.Second)
	for pid == 0 {
		select {
		case <-deadline:
			t.Fatal("v1 helper did not start")
		default:
			data, _ := os.ReadFile(pidFile)
			_, _ = fmt.Sscanf(string(data), "%d", &pid)
		}
	}
	if err := r.Stop(t.Context(), RunnerStopRequest{PluginID: loaded.Manifest.ID, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if err := <-invokeDone; err == nil {
		t.Fatal("active v1 invocation unexpectedly succeeded")
	}
	assertProcessGroupGone(t, pid)
}

// Gate: arg-vector exec, no shell. Shell metacharacters in the payload reach the
// plugin as literal data over stdin; they are never interpreted as a command.
func TestSystemRunnerNoShellInjection(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	canary := filepath.Join(t.TempDir(), "pwned")
	// The script echoes the raw stdin back as the result string. If the payload
	// were ever passed through a shell, the embedded command would create canary.
	script := "#!/bin/sh\nIN=$(cat)\nprintf '{\"ok\":true,\"result\":%s}\\n' \"$(printf '%s' \"$IN\" | sed 's/\\\\/\\\\\\\\/g;s/\"/\\\\\"/g' | sed 's/^/\"/;s/$/\"/')\"\n"
	loaded := makeBundle(t, "p.noshell", script, "")
	payload := json.RawMessage(`{"x":"; touch ` + canary + ` ;"}`)
	if _, err := startInvoke(t, r, loaded, "plan", payload); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("shell injection: canary file was created at %s", canary)
	}
}

// Gate: confined working directory.
func TestSystemRunnerConfinedCwd(t *testing.T) {
	rtDir := t.TempDir()
	r := newRunner(t, SystemRunnerOptions{RuntimeDir: rtDir})
	loaded := makeBundle(t, "p.cwd", "#!/bin/sh\nread line\nprintf '{\"ok\":true,\"result\":{\"pwd\":\"%s\"}}\\n' \"$(pwd)\"\n", "")
	resp, err := startInvoke(t, r, loaded, "plan", nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	var got struct {
		PWD string `json:"pwd"`
	}
	_ = json.Unmarshal(resp.Result, &got)
	want, _ := filepath.EvalSymlinks(filepath.Join(rtDir, "p.cwd"))
	gotResolved, _ := filepath.EvalSymlinks(got.PWD)
	if gotResolved != want {
		t.Fatalf("cwd not confined: got %q want %q", gotResolved, want)
	}
}

// Gate: environment allowlist only.
func TestSystemRunnerEnvAllowlist(t *testing.T) {
	t.Setenv("LATTICE_TEST_ALLOWED", "yes")
	t.Setenv("LATTICE_TEST_SECRET", "leak")
	r := newRunner(t, SystemRunnerOptions{EnvAllowlist: []string{"LATTICE_TEST_ALLOWED"}})
	loaded := makeBundle(t, "p.env", "#!/bin/sh\nread line\nprintf '{\"ok\":true,\"result\":{\"allowed\":\"%s\",\"secret\":\"%s\"}}\\n' \"$LATTICE_TEST_ALLOWED\" \"$LATTICE_TEST_SECRET\"\n", "")
	resp, err := startInvoke(t, r, loaded, "plan", nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	var got struct {
		Allowed string `json:"allowed"`
		Secret  string `json:"secret"`
	}
	_ = json.Unmarshal(resp.Result, &got)
	if got.Allowed != "yes" {
		t.Fatalf("allowlisted var not forwarded: %q", got.Allowed)
	}
	if got.Secret != "" {
		t.Fatalf("non-allowlisted var leaked: %q", got.Secret)
	}
}

func TestSystemRunnerChildEnvDropsReservedRuntimeVariables(t *testing.T) {
	for _, name := range []string{"LATTICE_RUNTIME_PROTOCOL", "LATTICE_RUNTIME_GENERATION", "LATTICE_HOST_RESPONSE_FD"} {
		t.Setenv(name, "hostile")
	}
	r := newRunner(t, SystemRunnerOptions{EnvAllowlist: []string{"LATTICE_RUNTIME_PROTOCOL", "LATTICE_RUNTIME_GENERATION", "LATTICE_HOST_RESPONSE_FD"}})
	for _, entry := range r.childEnv() {
		if strings.HasPrefix(entry, "LATTICE_RUNTIME_") || strings.HasPrefix(entry, "LATTICE_HOST_RESPONSE_FD=") {
			t.Fatalf("reserved environment escaped allowlist: %q", entry)
		}
	}
}

func TestSystemRunnerV1FailureNeverReturnsRawStderr(t *testing.T) {
	const secret = "SECRET-CANARY-DO-NOT-PERSIST"
	var logs []string
	r := newRunner(t, SystemRunnerOptions{Logf: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }})
	loaded := makeBundle(t, "p.stderr-secret", "#!/bin/sh\necho '"+secret+"' >&2\nexit 1\n", "")
	_, err := startInvoke(t, r, loaded, "fail", nil)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("external error leaked stderr: %v", err)
	}
	if len(logs) == 0 || strings.Contains(strings.Join(logs, "\n"), secret) || !strings.Contains(strings.Join(logs, "\n"), "stderr_bytes=") {
		t.Fatalf("metadata-only log contract violated: %v", logs)
	}
}

func TestSystemRunnerV1EnforcesCumulativeStdoutAcrossBlankLines(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	loaded := makeBundle(t, "p.blank-flood", "#!/bin/sh\nread line\ni=0; while [ $i -lt 100 ]; do echo; i=$((i+1)); done\necho '{\"ok\":true}'\n", "")
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	_, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 64, StderrBytes: 64, HostCalls: 0}}})
	if err == nil || !strings.Contains(err.Error(), "cumulative stdout limit") {
		t.Fatalf("error=%v", err)
	}
}

func TestSystemRunnerV1CountsCRLFWireBytes(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	loaded := makeBundle(t, "p.crlf-flood", "#!/bin/sh\nread line\ni=0; while [ $i -lt 30 ]; do printf '\\r\\n'; i=$((i+1)); done\nprintf '{\"ok\":true}'\n", "")
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	_, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 64, StderrBytes: 64, HostCalls: 0}}})
	if err == nil || !strings.Contains(err.Error(), "cumulative stdout limit") {
		t.Fatalf("error=%v", err)
	}
}

func TestSystemRunnerV1UnterminatedFrameExactWireBudget(t *testing.T) {
	const frame = `{"ok":true}`
	for _, tc := range []struct {
		name    string
		budget  int
		wantErr bool
	}{
		{name: "exact", budget: len(frame)},
		{name: "one-over", budget: len(frame) - 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunner(t, SystemRunnerOptions{})
			loaded := makeBundle(t, "p.unterminated-"+tc.name, "#!/bin/sh\nread line\nprintf '"+frame+"'\n", "")
			if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
				t.Fatal(err)
			}
			resp, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: tc.budget, StderrBytes: 64, HostCalls: 0}}})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "stdout") {
					t.Fatalf("response=%+v error=%v", resp, err)
				}
			} else if err != nil || !resp.OK {
				t.Fatalf("response=%+v error=%v", resp, err)
			}
		})
	}
}

func TestSystemRunnerV1ManualPipeOwnershipDoesNotLeakFDs(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{CrashThreshold: 100})
	loaded := makeBundle(t, "p.fd-ownership", "#!/bin/sh\nread line\ncase \"$line\" in *fail*) exit 1 ;; esac\nprintf '{\"ok\":true}'\n", "")
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	before := countOpenFDs(t)
	for i := 0; i < 25; i++ {
		if _, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Action: "ok"}); err != nil {
			t.Fatalf("successful invocation %d: %v", i, err)
		}
		if _, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Action: "fail"}); err == nil {
			t.Fatalf("failed invocation %d succeeded", i)
		}
	}
	after := countOpenFDs(t)
	if after > before+2 {
		t.Fatalf("v1 invocations leaked descriptors: before=%d after=%d", before, after)
	}
}

func TestSystemRunnerRetireExposesGenerationCleanupResidual(t *testing.T) {
	loaded := makeBundle(t, "p.cleanup-residual", "#!/bin/sh\nread line\nprintf '{\"ok\":true}'\n", "")
	r := newRunner(t, SystemRunnerOptions{})
	removeErr := errors.New("remove workdir failed")
	r.removeAll = func(string) error { return removeErr }
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	if err := r.ActivateGeneration(loaded.Manifest.ID, 1); err != nil {
		t.Fatal(err)
	}
	err := r.RetireGeneration(t.Context(), loaded.Manifest.ID, 1)
	var cleanupErr *GenerationCleanupError
	if !errors.As(err, &cleanupErr) || !errors.Is(err, removeErr) || cleanupErr.PluginID != loaded.Manifest.ID || cleanupErr.Generation != 1 {
		t.Fatalf("retirement residual=%v typed=%+v", err, cleanupErr)
	}
}

func TestTransportWaitAbortReportsTypedResidual(t *testing.T) {
	tm := &systemWorkerTransport{pgid: 4242, abortDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := tm.waitAbort(ctx)
	var residual *processGroupResidualError
	if !errors.As(err, &residual) || residual.PGID != 4242 || residual.Stage != "abort-pending" {
		t.Fatalf("waitAbort error=%v residual=%#v", err, residual)
	}
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	count := 0
	for fd := 0; fd < 1024; fd++ {
		var stat syscall.Stat_t
		if syscall.Fstat(fd, &stat) == nil {
			count++
		}
	}
	return count
}

func TestSystemRunnerV1EnforcesCumulativeStdoutAcrossHostCalls(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	script := "#!/bin/sh\nread line\ni=1; while [ $i -le 4 ]; do echo '{\"host_call\":{\"id\":\"h'$i'\",\"method\":\"log.write\",\"params\":{\"level\":\"info\",\"message\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}}}'; read resp <&3; i=$((i+1)); done\necho '{\"ok\":true}'\n"
	loaded := makeBundle(t, "p.host-flood", script, "")
	broker := newTestBroker(t, loaded.Manifest.ID, []string{"log:write"}, HostServices{Log: noopTestLog{}})
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded, Broker: broker}); err != nil {
		t.Fatal(err)
	}
	_, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 5_000, StdoutBytes: 300, StderrBytes: 64, HostCalls: 8}}})
	if err == nil || !strings.Contains(err.Error(), "cumulative stdout limit") {
		t.Fatalf("error=%v", err)
	}
}

func TestSystemRunnerV1NonzeroExitAfterResultReturnsWarning(t *testing.T) {
	var logs []string
	r := newRunner(t, SystemRunnerOptions{Logf: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }})
	loaded := makeBundle(t, "p.exit-after-result", "#!/bin/sh\nread line\necho '{\"ok\":true,\"result\":{\"done\":true}}'\nexit 7\n", "")
	resp, err := startInvoke(t, r, loaded, "run", nil)
	if err != nil || !resp.OK || len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "exit status 7") {
		t.Fatalf("response=%+v err=%v", resp, err)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "exit status 7") {
		t.Fatalf("logs=%v", logs)
	}
}

func TestSystemRunnerV1ReplyThenDeadlineIsFailureAndReaped(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	r := newRunner(t, SystemRunnerOptions{StopGrace: 10 * time.Millisecond})
	loaded := makeBundle(t, "p.reply-hang", "#!/bin/sh\nread line\necho $$ > '"+pidFile+"'\necho '{\"ok\":true}'\nsleep 30\n", "")
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	_, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 50, StdoutBytes: 1024, StderrBytes: 1024, HostCalls: 0}}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v want deadline", err)
	}
	data, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var pid int
	_, _ = fmt.Sscanf(string(data), "%d", &pid)
	assertProcessGroupGone(t, pid)
}

func TestSystemRunnerV1TimeoutKillsIgnoreTermDescendantHoldingPipes(t *testing.T) {
	dir := t.TempDir()
	pgidFile := filepath.Join(dir, "pgid")
	childFile := filepath.Join(dir, "child")
	r := newRunner(t, SystemRunnerOptions{StopGrace: 20 * time.Millisecond})
	script := "#!/bin/sh\nread line\necho $$ > '" + pgidFile + "'\n(trap '' TERM; while :; do sleep 1; done) &\necho $! > '" + childFile + "'\nexit 0\n"
	loaded := makeBundle(t, "p.descendant-timeout", script, "")
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	_, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 100, StdoutBytes: 1024, StderrBytes: 1024, HostCalls: 0}}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v want deadline", err)
	}
	pgid := waitForPIDFile(t, pgidFile)
	child := waitForPIDFile(t, childFile)
	assertPIDGone(t, child)
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("v1 process group %d survived timeout: %v", pgid, err)
	}
}

func TestSystemRunnerV1ResultKillsIgnoreTermDescendantHoldingPipes(t *testing.T) {
	dir := t.TempDir()
	pgidFile := filepath.Join(dir, "pgid")
	childFile := filepath.Join(dir, "child")
	r := newRunner(t, SystemRunnerOptions{StopGrace: 20 * time.Millisecond})
	script := "#!/bin/sh\nread line\necho $$ > '" + pgidFile + "'\n(trap '' TERM; while :; do sleep 1; done) &\necho $! > '" + childFile + "'\necho '{\"ok\":true,\"result\":{\"done\":true}}'\nexit 0\n"
	loaded := makeBundle(t, "p.descendant-result", script, "")
	resp, err := startInvoke(t, r, loaded, "run", nil)
	if err != nil || !resp.OK {
		t.Fatalf("response=%+v err=%v", resp, err)
	}
	pgid := waitForPIDFile(t, pgidFile)
	child := waitForPIDFile(t, childFile)
	assertPIDGone(t, child)
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("v1 process group %d survived result teardown: %v", pgid, err)
	}
}

func waitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var pid int
			if _, err := fmt.Sscanf(string(data), "%d", &pid); err == nil && pid > 0 {
				return pid
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("PID file %s was not populated", path)
		case <-time.After(time.Millisecond):
		}
	}
}

func assertPIDGone(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process %d survived: %v", pid, err)
	}
}

func TestSystemRunnerPrepareCanceledWhileQueuedLeavesNoArtifacts(t *testing.T) {
	runtimeDir := t.TempDir()
	r := newRunner(t, SystemRunnerOptions{RuntimeDir: runtimeDir})
	loaded := makeBundle(t, "p.queued-cancel", "#!/bin/sh\nexit 0\n", "")
	lock := r.startLock(loaded.Manifest.ID)
	lock.Lock()
	waiting := make(chan struct{})
	r.beforeStartLock = func() { close(waiting) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.Prepare(ctx, RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded})
		done <- err
	}()
	<-waiting
	cancel()
	lock.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Prepare error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, loaded.Manifest.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled queued Prepare left artifacts: %v", err)
	}
}

// Gate: invocation deadline kills a hung plugin.
func TestSystemRunnerTimeout(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{InvokeTimeout: 200 * time.Millisecond, StopGrace: 200 * time.Millisecond})
	loaded := makeBundle(t, "p.hang", "#!/bin/sh\nsleep 30\n", "")
	start := time.Now()
	_, err := startInvoke(t, r, loaded, "plan", nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took too long: %s", elapsed)
	}
}

// Gate: crash circuit breaker after repeated failures.
func TestSystemRunnerCircuitBreaker(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{CrashThreshold: 3})
	loaded := makeBundle(t, "p.crash", "#!/bin/sh\nexit 1\n", "")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Action: "plan"}); err == nil {
			t.Fatalf("invoke %d: expected failure", i)
		}
	}
	if _, err := r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Action: "plan"}); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("after threshold: want ErrCircuitOpen, got %v", err)
	}
}

// Gate: a successful invocation resets the failure counter (no premature trip).
func TestSystemRunnerBreakerResetsOnSuccess(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{CrashThreshold: 2})
	// fails when payload mentions "fail", succeeds otherwise
	script := "#!/bin/sh\nIN=$(cat)\ncase \"$IN\" in *fail*) exit 1 ;; esac\necho '{\"ok\":true}'\n"
	loaded := makeBundle(t, "p.reset", script, "")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	inv := func(p string) error {
		_, err := r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Action: "plan", Payload: json.RawMessage(`"` + p + `"`)})
		return err
	}
	_ = inv("fail")                   // 1 failure
	_ = inv("ok")                     // success -> reset
	_ = inv("fail")                   // 1 failure
	if err := inv("ok"); err != nil { // should still succeed (not tripped)
		t.Fatalf("breaker tripped prematurely: %v", err)
	}
}

// Gate (design-12 runtime review HIGH-1): a valid terminal reply followed by a
// non-zero exit (noisy teardown) must NOT count as a failure — the reply is
// returned and the circuit breaker stays closed even past CrashThreshold.
func TestSystemRunnerValidReplySurvivesNonZeroExit(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{CrashThreshold: 3})
	// drains stdin, writes a valid reply, then exits non-zero
	loaded := makeBundle(t, "p.noisyexit", "#!/bin/sh\nIN=$(cat)\necho '{\"ok\":true,\"message\":\"done\"}'\nexit 1\n", "")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 0; i < 6; i++ { // > CrashThreshold(3): breaker must never trip on a valid reply
		resp, err := r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Action: "plan"})
		if err != nil {
			t.Fatalf("invoke %d: unexpected error (valid reply must not trip the breaker): %v", i, err)
		}
		if !resp.OK || resp.Message != "done" {
			t.Fatalf("invoke %d: unexpected response %+v", i, resp)
		}
	}
}

// Gate: digest mismatch at start is rejected (TOCTOU defense).
func TestSystemRunnerDigestMismatch(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	loaded := makeBundle(t, "p.digest", "#!/bin/sh\necho '{\"ok\":true}'\n", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("want digest mismatch error, got %v", err)
	}
}

// A correct digest passes start.
func TestSystemRunnerDigestMatch(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	script := "#!/bin/sh\nread line\necho '{\"ok\":true}'\n"
	loaded := makeBundle(t, "p.digest2", script, DigestSHA256([]byte(script)))
	if _, err := startInvoke(t, r, loaded, "plan", nil); err != nil {
		t.Fatalf("valid digest start/invoke: %v", err)
	}
}

func TestSystemRunnerHonorsDeclaredStdoutBudget(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	script := `#!/bin/sh
read line
printf '{"ok":true,"result":"'
head -c 1049000 /dev/zero | tr '\000' a
printf '"}\n'
`
	loaded := makeBundle(t, "p.stdoutbudget", script, "")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	largeBudget := &InvokeBudgetSpec{TimeoutMS: 10_000, StdoutBytes: 2 << 20, StderrBytes: 1 << 10, HostCalls: 0}
	resp, err := r.Invoke(context.Background(), InvokeRequest{
		PluginID: loaded.Manifest.ID, Action: "call",
		Constraints: InvokeConstraints{Budget: largeBudget, BudgetLabel: "p.stdoutbudget/list"},
	})
	if err != nil {
		t.Fatalf("declared budget above old 1MiB default should allow the response: %v", err)
	}
	if !resp.OK || len(resp.Result) <= defaultMaxOutputBytes {
		t.Fatalf("expected successful >1MiB result, ok=%t len=%d", resp.OK, len(resp.Result))
	}

	smallBudget := &InvokeBudgetSpec{TimeoutMS: 10_000, StdoutBytes: 256 << 10, StderrBytes: 1 << 10, HostCalls: 0}
	_, err = r.Invoke(context.Background(), InvokeRequest{
		PluginID: loaded.Manifest.ID, Action: "call",
		Constraints: InvokeConstraints{Budget: smallBudget, BudgetLabel: "p.stdoutbudget/list"},
	})
	if err == nil || !strings.Contains(err.Error(), "stdout exceeded budget") {
		t.Fatalf("expected declared stdout budget failure, got %v", err)
	}
}

func TestSystemRunnerDefaultsAbsentBudgetWithWarnOnce(t *testing.T) {
	var logs []string
	r := newRunner(t, SystemRunnerOptions{Logf: func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}})
	loaded := makeBundle(t, "p.defaultbudget", "#!/bin/sh\nread line\necho '{\"ok\":true,\"result\":{\"ok\":true}}'\n", "")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 0; i < 2; i++ {
		resp, err := r.Invoke(context.Background(), InvokeRequest{
			PluginID: loaded.Manifest.ID, Action: "call",
			Constraints: InvokeConstraints{BudgetLabel: "p.defaultbudget/list"},
		})
		if err != nil || !resp.OK {
			t.Fatalf("invoke %d: resp=%+v err=%v", i, resp, err)
		}
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "has no declared budget") ||
		!strings.Contains(logs[0], "stdout_bytes=1048576") {
		t.Fatalf("absent budget should warn once with old defaults, logs=%+v", logs)
	}
}

func TestSystemRunnerSurfacesStderrTruncationOnSuccess(t *testing.T) {
	var logs []string
	r := newRunner(t, SystemRunnerOptions{Logf: func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}})
	script := `#!/bin/sh
read line
head -c 2048 /dev/zero | tr '\000' e >&2
echo '{"ok":true,"message":"done","result":{"ok":true}}'
`
	loaded := makeBundle(t, "p.stderrbudget", script, "")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	resp, err := r.Invoke(context.Background(), InvokeRequest{
		PluginID: loaded.Manifest.ID, Action: "call",
		Constraints: InvokeConstraints{
			Budget:      &InvokeBudgetSpec{TimeoutMS: 10_000, StdoutBytes: 1 << 10, StderrBytes: 64, HostCalls: 0},
			BudgetLabel: "p.stderrbudget/list",
		},
	})
	if err != nil || !resp.OK {
		t.Fatalf("stderr truncation on success must not fail: resp=%+v err=%v", resp, err)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "stderr truncated after 64 bytes") {
		t.Fatalf("missing stderr truncation warning: %+v", resp.Warnings)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "stderr truncated after 64 bytes") {
		t.Fatalf("missing host log for stderr truncation: %+v", logs)
	}
}

func TestSystemRunnerHonorsZeroHostCallBudget(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	script := `#!/bin/sh
read req
echo '{"host_call":{"id":"h1","method":"kv.get","params":{"key":"x"}}}'
`
	loaded := makeBundle(t, "p.nohostcalls", script, "")
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, err := r.Invoke(context.Background(), InvokeRequest{
		PluginID: loaded.Manifest.ID, Action: "call",
		Constraints: InvokeConstraints{
			Budget:      &InvokeBudgetSpec{TimeoutMS: 10_000, StdoutBytes: 1 << 10, StderrBytes: 1 << 10, HostCalls: 0},
			BudgetLabel: "p.nohostcalls/list",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "host-call limit 0") {
		t.Fatalf("expected zero host-call budget to fail loudly, got %v", err)
	}
}

func TestSystemRunnerV2StagesVerifiedSelectedRuntime(t *testing.T) {
	script := "#!/bin/sh\nread line\necho '{\"ok\":true,\"result\":{\"v2\":true}}'\n"
	archive := makeTestArchive(t,
		testArchiveEntry{name: "bin/linux-amd64/plugin", body: []byte(script)},
		testArchiveEntry{name: "ui/index.html", body: []byte("ui")},
	)
	m := testManifestForArchive(archive)
	extracted, err := ExtractBundleV2(t.TempDir(), m, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, artifactFileName), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded := Loaded{
		Manifest: m, Capabilities: append([]string(nil), m.Capabilities...), BundlePath: source,
		ArtifactPath: filepath.Join(source, artifactFileName), ArtifactDigest: m.Bundle.DigestSHA256,
		ExtractedRoot: extracted.Root, RuntimeEntry: "bin/linux-amd64/plugin", RuntimePath: extracted.RuntimePath,
		UIRoot: extracted.UIRoot, UIEntry: extracted.UIEntry, Inventory: extracted.Inventory,
		BundleLimits: DefaultBundleLimits(),
	}
	r := newRunner(t, SystemRunnerOptions{})
	resp, err := startInvoke(t, r, loaded, "call", nil)
	if err != nil || !resp.OK || string(resp.Result) != `{"v2":true}` {
		t.Fatalf("v2 runtime failed: resp=%+v err=%v", resp, err)
	}
}

func TestSystemRunnerV2RejectsZeroGenerationBeforeStaging(t *testing.T) {
	runtimeDir := t.TempDir()
	r := NewSystemRunner(SystemRunnerOptions{RuntimeDir: runtimeDir})
	loaded := makeBundle(t, "p.zero", "#!/bin/sh\nexit 0\n", "")
	loaded.Manifest.Runtime = &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV2}
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded}); err == nil || !strings.Contains(err.Error(), "generation 0") {
		t.Fatalf("zero generation error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, loaded.Manifest.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("zero generation touched runtime path: %v", err)
	}
}

func TestSystemRunnerV2PassesGenerationEnvironmentAboveOne(t *testing.T) {
	t.Setenv("LATTICE_TEST_V2_HELPER", "1")
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, artifactFileName), binary, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := Loaded{
		Manifest:   Manifest{ID: "p.genenv", Name: "generation env", Type: TypeSystem, Runtime: &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV2}},
		BundlePath: dir,
	}
	r := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), EnvAllowlist: []string{"LATTICE_TEST_V2_HELPER"}})
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 7, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	rsp, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 7, Action: "generation"})
	if err != nil || !rsp.OK {
		t.Fatalf("generation 7 invoke response=%+v err=%v", rsp, err)
	}
	if err := r.Stop(t.Context(), RunnerStopRequest{PluginID: loaded.Manifest.ID, Generation: 7}); err != nil {
		t.Fatal(err)
	}
}

func TestSystemRunnerV2RejectsSourceAndCacheTampering(t *testing.T) {
	archive := makeTestArchive(t,
		testArchiveEntry{name: "bin/linux-amd64/plugin", body: []byte("#!/bin/sh\necho '{\"ok\":true}'\n")},
		testArchiveEntry{name: "ui/index.html", body: []byte("ui")},
	)
	m := testManifestForArchive(archive)
	cache := t.TempDir()
	extracted, err := ExtractBundleV2(cache, m, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	artifactPath := filepath.Join(source, artifactFileName)
	if err := os.WriteFile(artifactPath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded := Loaded{
		Manifest: m, Capabilities: m.Capabilities, BundlePath: source,
		ArtifactPath: artifactPath, ArtifactDigest: m.Bundle.DigestSHA256,
		ExtractedRoot: extracted.Root, RuntimeEntry: "bin/linux-amd64/plugin", RuntimePath: extracted.RuntimePath,
		Inventory: extracted.Inventory, BundleLimits: DefaultBundleLimits(),
	}

	if err := os.WriteFile(artifactPath, []byte("tampered source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newRunner(t, SystemRunnerOptions{}).Start(context.Background(), RunnerStartRequest{PluginID: m.ID, Loaded: loaded}); err == nil || !strings.Contains(err.Error(), "bundle digest") {
		t.Fatalf("expected source bundle digest rejection, got %v", err)
	}

	loaded.BundleLimits.MaxCompressedBytes = int64(len(archive) + 1)
	if err := os.WriteFile(artifactPath, bytes.Repeat([]byte("x"), len(archive)+2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newRunner(t, SystemRunnerOptions{}).Start(context.Background(), RunnerStartRequest{PluginID: m.ID, Loaded: loaded}); err == nil || !strings.Contains(err.Error(), "compressed size") {
		t.Fatalf("expected bounded source archive rejection, got %v", err)
	}

	if err := os.WriteFile(artifactPath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extracted.RuntimePath, []byte("tampered cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newRunner(t, SystemRunnerOptions{}).Start(context.Background(), RunnerStartRequest{PluginID: m.ID, Loaded: loaded}); err == nil || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("expected cached runtime rejection, got %v", err)
	}
}

func TestSystemRunnerHostCallBridge(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	script := `#!/bin/sh
read req
echo '{"host_call":{"id":"h1","method":"rpc.call","params":{"service":"test.svc","method":"list","request":{"want":"nodes"}}}}'
read rpc <&3
echo '{"host_call":{"id":"h2","method":"http.do","params":{"method":"POST","url":"https://example.com/api","body":"payload"}}}'
read http <&3
printf '{"ok":true,"result":{"rpc":%s,"http":%s}}\n' "$rpc" "$http"
`
	loaded := makeBundle(t, "p.bridge", script, "")
	loaded.Manifest.Capabilities = []string{"rpc:call", "http:egress"}
	loaded.Capabilities = []string{"rpc:call", "http:egress"}
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	broker, err := NewBroker(loaded, HostServices{
		HTTP: services,
		RPC: fakeRPCHost(func(ctx context.Context, caller, service, method string, request []byte) ([]byte, error) {
			if caller != "p.bridge" || service != "test.svc" || method != "list" || string(request) != `{"want":"nodes"}` {
				t.Fatalf("unexpected rpc call: caller=%s service=%s method=%s request=%s", caller, service, method, request)
			}
			return []byte(`{"nodes":2}`), nil
		}),
		Audit:    services,
		GuardURL: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.rpcGrant = RPCGrant{"test.svc": {"list": {}}}
	if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Loaded: loaded, Broker: broker}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	resp, err := r.Invoke(context.Background(), InvokeRequest{PluginID: loaded.Manifest.ID, Action: "call"})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	var got struct {
		RPC struct {
			HostResponse struct {
				OK     bool `json:"ok"`
				Result struct {
					Nodes int `json:"nodes"`
				} `json:"result"`
			} `json:"host_response"`
		} `json:"rpc"`
		HTTP struct {
			HostResponse struct {
				OK     bool `json:"ok"`
				Result struct {
					StatusCode int `json:"status_code"`
				} `json:"result"`
			} `json:"host_response"`
		} `json:"http"`
	}
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("decode result: %v (%s)", err, resp.Result)
	}
	if !got.RPC.HostResponse.OK || got.RPC.HostResponse.Result.Nodes != 2 {
		t.Fatalf("rpc host response wrong: %+v", got.RPC.HostResponse)
	}
	if !got.HTTP.HostResponse.OK || got.HTTP.HostResponse.Result.StatusCode != 202 || services.httpCalls != 1 {
		t.Fatalf("http host response wrong: %+v calls=%d", got.HTTP.HostResponse, services.httpCalls)
	}
}

func TestSystemRunnerFreshHostResponseOversizeThenSmallStaysSynchronized(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	script := `#!/bin/sh
read req
echo '{"host_call":{"id":"h1","method":"rpc.call","params":{"service":"test.svc","method":"get","request":{"sequence":1}}}}'
IFS= read -r exact <&3
case "$exact" in *'"ok":true'*) exact_ok=true ;; *) exact_ok=false ;; esac
echo '{"host_call":{"id":"h2","method":"rpc.call","params":{"service":"test.svc","method":"get","request":{"sequence":2}}}}'
IFS= read -r over <&3
case "$over" in *'"error":"host response exceeds protocol limits"'*) over_ok=true ;; *) over_ok=false ;; esac
echo '{"host_call":{"id":"h3","method":"rpc.call","params":{"service":"test.svc","method":"get","request":{"sequence":3}}}}'
IFS= read -r small <&3
case "$small" in *'"small":true'*) small_ok=true ;; *) small_ok=false ;; esac
printf '{"ok":true,"result":{"exact_ok":%s,"over_ok":%s,"small_ok":%s}}\n' "$exact_ok" "$over_ok" "$small_ok"
`
	loaded := makeBundle(t, "p.response-boundary", script, "")
	loaded.Manifest.Capabilities = []string{"rpc:call"}
	loaded.Capabilities = []string{"rpc:call"}
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	callCount := 0
	broker, err := NewBroker(loaded, HostServices{RPC: fakeRPCHost(func(_ context.Context, _, _, _ string, _ []byte) ([]byte, error) {
		callCount++
		switch callCount {
		case 1:
			return exactHostPayload(sdkplugin.DefaultMaxHostResponsePayloadBytes), nil
		case 2:
			return exactHostPayload(sdkplugin.DefaultMaxHostResponsePayloadBytes + 1), nil
		default:
			return []byte(`{"small":true}`), nil
		}
	}), Audit: services})
	if err != nil {
		t.Fatal(err)
	}
	broker.rpcGrant = RPCGrant{"test.svc": {"get": {}}}
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded, Broker: broker}); err != nil {
		t.Fatal(err)
	}
	resp, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 1, Action: "call"})
	if err != nil || !resp.OK || callCount != 3 {
		t.Fatalf("response=%+v calls=%d error=%v", resp, callCount, err)
	}
	var result struct {
		ExactOK bool `json:"exact_ok"`
		OverOK  bool `json:"over_ok"`
		SmallOK bool `json:"small_ok"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !result.ExactOK || !result.OverOK || !result.SmallOK {
		t.Fatalf("host response sequence=%+v", result)
	}
}

func TestDispatchHostCallOperatorHTTP(t *testing.T) {
	services := &fakeHostServices{kvValues: map[string][]byte{}}
	broker, err := NewBroker(Loaded{
		Manifest: Manifest{ID: "p.operator", Name: "Operator", Type: TypeSystem,
			Capabilities: []string{"http:operator-target"}},
		Capabilities: []string{"http:operator-target"},
	}, HostServices{
		OperatorHTTP:     services,
		Audit:            services,
		GuardOperatorURL: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	boundCtx, err := BindOperatorTargets(context.Background(), []string{"https://10.0.0.5/secret"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatchHostCall(boundCtx, broker, systemHostCall{
		ID: "operator", Method: "http.operator.do",
		Params: json.RawMessage(`{"method":"PATCH","url":"https://10.0.0.5/secret","body":"payload"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if services.operatorHTTPCalls != 1 || !bytes.Contains(result, []byte(`"status_code":202`)) {
		t.Fatalf("operator host call result=%s calls=%d", result, services.operatorHTTPCalls)
	}
}

func TestSystemRunnerNotArmed(t *testing.T) {
	r := newRunner(t, SystemRunnerOptions{})
	if _, err := r.Invoke(context.Background(), InvokeRequest{PluginID: "nope", Action: "plan"}); err == nil {
		t.Fatalf("expected error invoking un-armed plugin")
	}
}

// Gate: output cap keeps a flooding plugin's captured output bounded.
func TestCappedBuffer(t *testing.T) {
	c := &cappedBuffer{limit: 100}
	for i := 0; i < 1000; i++ {
		n, err := c.Write([]byte("0123456789"))
		if err != nil || n != 10 {
			t.Fatalf("write reported n=%d err=%v (must report full consumption)", n, err)
		}
	}
	if got := len(c.Bytes()); got != 100 {
		t.Fatalf("capped buffer stored %d bytes, want 100", got)
	}
}

type fakeRPCHost func(ctx context.Context, caller, service, method string, request []byte) ([]byte, error)

func (f fakeRPCHost) Call(ctx context.Context, caller, service, method string, request []byte) ([]byte, error) {
	return f(ctx, caller, service, method, request)
}

func (f fakeRPCHost) CallGranted(ctx context.Context, caller string, grant RPCGrant, service, method string, request []byte) ([]byte, error) {
	if _, ok := grant[service][method]; !ok {
		return nil, ErrRPCDenied
	}
	return f(ctx, caller, service, method, request)
}

// Integration: RuntimeManager routes Invoke to the system runner, and refuses to
// invoke a plugin backed by the noop runner.
func TestRuntimeManagerInvokeRoutesToSystemRunner(t *testing.T) {
	rtDir := t.TempDir()
	sys := NewSystemRunner(SystemRunnerOptions{RuntimeDir: rtDir})
	mgr := NewRuntimeManagerWithOptions(RuntimeManagerOptions{Runners: map[string]Runner{TypeSystem: sys}})
	loaded := makeBundle(t, "p.mgr", "#!/bin/sh\nread line\necho '{\"ok\":true,\"result\":{\"ran\":true}}'\n", "")
	if _, err := mgr.Start(context.Background(), loaded); err != nil {
		t.Fatalf("manager Start: %v", err)
	}
	resp, err := mgr.Invoke(context.Background(), "p.mgr", "plan", nil)
	if err != nil || !resp.OK || string(resp.Result) != `{"ran":true}` {
		t.Fatalf("manager Invoke: resp=%+v err=%v", resp, err)
	}

	// noop-backed plugin (worker type falls through to noop) cannot be invoked.
	noopLoaded := Loaded{
		Manifest:     Manifest{ID: "p.noop", Name: "x", Type: TypeWorker, Capabilities: []string{"kv:read"}},
		Capabilities: []string{"kv:read"},
		BundlePath:   t.TempDir(),
	}
	if _, err := mgr.Start(context.Background(), noopLoaded); err != nil {
		t.Fatalf("noop Start: %v", err)
	}
	if _, err := mgr.Invoke(context.Background(), "p.noop", "plan", nil); err == nil || !strings.Contains(err.Error(), "does not support invocation") {
		t.Fatalf("noop invoke: want unsupported error, got %v", err)
	}

	// After Stop, the plugin can no longer be invoked.
	if _, err := mgr.Stop("p.mgr", "disabled"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := mgr.Invoke(context.Background(), "p.mgr", "plan", nil); err == nil {
		t.Fatalf("invoke after stop should fail")
	}
}

func TestKVGetResponseDropsRawValueWhenLarge(t *testing.T) {
	// The kv.get response rides one bounded response frame. Carrying the value
	// twice (raw + base64) doubles the frame; past
	// ~430 KiB of value the plugin dies mid-invocation and the runner sees a
	// broken pipe. Base64-only past the small threshold keeps it inside.
	big := make([]byte, 600<<10)
	for i := range big {
		big[i] = byte('a' + i%26)
	}
	services := &fakeHostServices{kvValues: map[string][]byte{
		"plugin:p.kv/big":   big,
		"plugin:p.kv/small": []byte("green"),
	}}
	broker := newTestBroker(t, "p.kv", []string{"kv:read"}, HostServices{KV: services, Audit: services})

	call := systemHostCall{ID: "h1", Method: "kv.get"}
	params, _ := json.Marshal(map[string]string{"key": "big"})
	call.Params = params
	out, err := dispatchHostCall(context.Background(), broker, call)
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		OK          bool   `json:"ok"`
		Value       string `json:"value"`
		ValueBase64 string `json:"value_base64"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.ValueBase64 == "" {
		t.Fatalf("big value lost its base64 encoding: %s", string(out)[:120])
	}
	if resp.Value != "" {
		t.Fatalf("big value carried the raw duplicate (%d bytes raw) — frame would exceed the plugin's read cap", len(resp.Value))
	}

	params2, _ := json.Marshal(map[string]string{"key": "small"})
	call.Params = params2
	out2, err := dispatchHostCall(context.Background(), broker, call)
	if err != nil {
		t.Fatal(err)
	}
	var resp2 struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(out2, &resp2); err != nil {
		t.Fatal(err)
	}
	if resp2.Value != "green" {
		t.Fatalf("small value should keep its raw form for debuggability: %s", string(out2)[:120])
	}
}
