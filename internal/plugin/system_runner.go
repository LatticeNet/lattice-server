package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Tier-2 system runner (design-08): executes trusted, first-party / operator
// audited plugins as short-lived, arg-vector subprocesses. Each invocation is a
// FRESH process whose lifetime is exactly one action and is bounded by a
// deadline, so there is no long-running daemon to heartbeat or reap. The runner
// never hands a plugin raw host handles; the plugin returns a result (e.g. a
// rendered plan) that the host then enacts under its OWN privileges via the
// existing plan->approve->apply path — so the runner cannot bypass approvals.

const (
	defaultInvokeTimeout  = 10 * time.Second
	defaultStopGrace      = 3 * time.Second
	defaultMaxOutputBytes = 1 << 20 // 1 MiB
	defaultCrashThreshold = 5
)

// ErrCircuitOpen is returned once a plugin has failed CrashThreshold times in a
// row. The operator must disable+re-enable (restart) the plugin to reset it; a
// flapping plugin cannot keep consuming resources.
var ErrCircuitOpen = errors.New("plugin circuit breaker open")

// SystemRunnerOptions configures the trusted-subprocess runner.
type SystemRunnerOptions struct {
	// RuntimeDir is the root under which each plugin gets a confined 0700 working
	// directory (RuntimeDir/<pluginID>) holding a 0700 copy of its verified
	// artifact. Required.
	RuntimeDir string
	// EnvAllowlist names the environment variables forwarded to the plugin. Every
	// other variable is stripped; a fixed safe PATH is always provided.
	EnvAllowlist []string
	// InvokeTimeout bounds one invocation (default 10s).
	InvokeTimeout time.Duration
	// StopGrace is the SIGTERM->SIGKILL window for a timed-out/cancelled process
	// (default 3s).
	StopGrace time.Duration
	// MaxOutputBytes caps captured stdout and (separately) stderr per invocation
	// (default 1 MiB), so a plugin cannot exhaust host memory by flooding output.
	MaxOutputBytes int
	// CrashThreshold trips the circuit breaker after this many consecutive failed
	// invocations (default 5).
	CrashThreshold int
}

type systemPluginState struct {
	execPath string
	workDir  string
	failures int
	tripped  bool
}

// SystemRunner implements Runner and Invoker.
type SystemRunner struct {
	opts SystemRunnerOptions
	mu   sync.Mutex
	st   map[string]*systemPluginState
}

// NewSystemRunner returns a system runner with the given options and safe
// defaults for any zero-valued bound.
func NewSystemRunner(opts SystemRunnerOptions) *SystemRunner {
	if opts.InvokeTimeout <= 0 {
		opts.InvokeTimeout = defaultInvokeTimeout
	}
	if opts.StopGrace <= 0 {
		opts.StopGrace = defaultStopGrace
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = defaultMaxOutputBytes
	}
	if opts.CrashThreshold <= 0 {
		opts.CrashThreshold = defaultCrashThreshold
	}
	return &SystemRunner{opts: opts, st: map[string]*systemPluginState{}}
}

func (r *SystemRunner) Name() string { return "system" }

// Start re-verifies the manifest-pinned digest of the artifact at the FIXED
// bundle path (TOCTOU defense in case the bundle changed after load), copies the
// bytes into a confined per-plugin 0700 working dir, and arms the runner. It
// always executes the staged 0700 copy, never the (possibly read-only or
// swapped) bundle file, and never resolves a manifest-controlled path.
func (r *SystemRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	if err := ctx.Err(); err != nil {
		return RunnerStartResult{}, err
	}
	if r.opts.RuntimeDir == "" {
		return RunnerStartResult{}, errors.New("system runner requires a RuntimeDir")
	}
	if req.Loaded.BundlePath == "" {
		return RunnerStartResult{}, errors.New("loaded plugin has no bundle path")
	}
	pluginID := req.PluginID
	if pluginID == "" {
		pluginID = req.Loaded.Manifest.ID
	}
	if !validPluginID(pluginID) {
		return RunnerStartResult{}, fmt.Errorf("invalid plugin id %q", pluginID)
	}

	artifactPath := filepath.Join(req.Loaded.BundlePath, artifactFileName)
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return RunnerStartResult{}, fmt.Errorf("read artifact: %w", err)
	}
	if req.Loaded.Manifest.DigestSHA256 != "" {
		if err := verifyDigest(req.Loaded.Manifest.DigestSHA256, data); err != nil {
			return RunnerStartResult{}, fmt.Errorf("artifact digest mismatch at start: %w", err)
		}
	}

	workDir := filepath.Join(r.opts.RuntimeDir, pluginID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return RunnerStartResult{}, fmt.Errorf("create plugin runtime dir: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		return RunnerStartResult{}, fmt.Errorf("secure plugin runtime dir: %w", err)
	}
	execPath := filepath.Join(workDir, "artifact")
	if err := writeFileAtomic(execPath, data, 0o700); err != nil {
		return RunnerStartResult{}, fmt.Errorf("stage artifact: %w", err)
	}

	r.mu.Lock()
	r.st[pluginID] = &systemPluginState{execPath: execPath, workDir: workDir}
	r.mu.Unlock()
	return RunnerStartResult{Message: "system runner armed (subprocess execution enabled)"}, nil
}

// Stop clears the plugin's staged state and removes its runtime dir. In-flight
// invocations are bound to their own context and terminate independently.
func (r *SystemRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	r.mu.Lock()
	st := r.st[req.PluginID]
	delete(r.st, req.PluginID)
	r.mu.Unlock()
	if st != nil {
		_ = os.RemoveAll(st.workDir)
	}
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

// Invoke runs the plugin for one action and returns its decoded reply. The
// process is spawned with arg-vector exec (NO shell, so payload content can never
// be interpreted as a command), a confined working directory, an allowlisted
// environment, capped output, and a deadline that escalates SIGTERM->SIGKILL.
// Repeated failures trip the circuit breaker. A crashing plugin yields an error,
// never a host crash.
func (r *SystemRunner) Invoke(ctx context.Context, req InvokeRequest) (InvokeResponse, error) {
	r.mu.Lock()
	st := r.st[req.PluginID]
	tripped := st != nil && st.tripped
	execPath, workDir := "", ""
	if st != nil {
		execPath, workDir = st.execPath, st.workDir
	}
	r.mu.Unlock()
	if st == nil {
		return InvokeResponse{}, fmt.Errorf("plugin %q is not armed on the system runner", req.PluginID)
	}
	if tripped {
		return InvokeResponse{}, fmt.Errorf("%w: %s", ErrCircuitOpen, req.PluginID)
	}

	input, err := json.Marshal(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{Action: req.Action, Payload: req.Payload})
	if err != nil {
		return InvokeResponse{}, fmt.Errorf("marshal invoke request: %w", err)
	}
	input = append(input, '\n')

	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, r.opts.InvokeTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, execPath)
	cmd.Dir = workDir
	cmd.Env = r.childEnv()
	cmd.Stdin = bytes.NewReader(input)
	stdout := &cappedBuffer{limit: r.opts.MaxOutputBytes}
	stderr := &cappedBuffer{limit: r.opts.MaxOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Graceful stop: send SIGTERM when runCtx is done, then SIGKILL after grace.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = r.opts.StopGrace

	if runErr := cmd.Run(); runErr != nil {
		r.recordFailure(req.PluginID)
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return InvokeResponse{}, fmt.Errorf("plugin %q invocation timed out after %s", req.PluginID, r.opts.InvokeTimeout)
		}
		return InvokeResponse{}, fmt.Errorf("plugin %q invocation failed: %w (stderr: %s)", req.PluginID, runErr, truncForErr(stderr.Bytes()))
	}

	var reply struct {
		OK      bool            `json:"ok"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
		Plan    json.RawMessage `json:"plan"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &reply); err != nil {
		r.recordFailure(req.PluginID)
		return InvokeResponse{}, fmt.Errorf("plugin %q returned invalid JSON: %w", req.PluginID, err)
	}
	result := reply.Result
	if len(result) == 0 {
		result = reply.Plan // tolerate the bootstrap template's {"plan":...} shape
	}
	r.recordSuccess(req.PluginID)
	if !reply.OK {
		return InvokeResponse{OK: false, Message: reply.Message, Result: result},
			fmt.Errorf("plugin %q reported failure: %s", req.PluginID, reply.Message)
	}
	return InvokeResponse{OK: true, Message: reply.Message, Result: result}, nil
}

func (r *SystemRunner) recordFailure(pluginID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.st[pluginID]
	if st == nil {
		return
	}
	st.failures++
	if st.failures >= r.opts.CrashThreshold {
		st.tripped = true
	}
}

func (r *SystemRunner) recordSuccess(pluginID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.st[pluginID]; st != nil {
		st.failures = 0
	}
}

// childEnv builds the allowlisted environment: only the named variables are
// forwarded, plus a fixed safe PATH unless PATH was itself allowlisted and set.
func (r *SystemRunner) childEnv() []string {
	env := make([]string, 0, len(r.opts.EnvAllowlist)+1)
	havePath := false
	for _, name := range r.opts.EnvAllowlist {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
			if name == "PATH" {
				havePath = true
			}
		}
	}
	if !havePath {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	return env
}

// cappedBuffer stores at most limit bytes and silently discards the rest while
// still reporting full consumption, so the child's output pipe never blocks and
// host memory stays bounded.
type cappedBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		c.buf.Write(p[:room])
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

func truncForErr(b []byte) string {
	const max = 512
	b = bytes.TrimSpace(b)
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}

// writeFileAtomic writes data to a temp file in the destination dir then renames
// it into place with mode, so a concurrent exec never sees a partial artifact.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
