package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
