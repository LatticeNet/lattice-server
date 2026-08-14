package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	defaultInvokeTimeout  = time.Duration(DefaultInvokeTimeoutMS) * time.Millisecond
	defaultStopGrace      = 3 * time.Second
	postKillReapAllowance = 2 * time.Second
	defaultMaxOutputBytes = DefaultInvokeStdoutBytes
	defaultCrashThreshold = 5
	defaultMaxHostCalls   = DefaultInvokeHostCalls
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
	// MaxHostCalls caps broker calls during one invocation (default 64).
	MaxHostCalls int
	// Logf receives host-visible runtime warnings. Nil disables warning logs.
	Logf func(format string, args ...any)
}

type systemPluginState struct {
	execPath        string
	workDir         string
	broker          *Broker
	failures        int
	startupFailures int
	tripped         bool
	pool            *systemPool
	isV2            bool
	generation      uint64
	admitted        bool
	retiring        bool
	cleanupOnce     sync.Once
	cleanupDone     chan struct{}
	refs            int
	forceAbort      bool
	v1Active        map[uint64]context.CancelFunc
	v1Next          uint64
	rootCtx         context.Context
	rootCancel      context.CancelFunc
}

// SystemRunner implements Runner and Invoker.
type SystemRunner struct {
	opts            SystemRunnerOptions
	mu              sync.Mutex
	st              map[string]map[uint64]*systemPluginState
	budgetWarnings  map[string]bool
	startLocks      map[string]*sync.Mutex
	draining        map[*systemPool]string
	closing         bool
	beforeStartLock func()
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
	if opts.MaxHostCalls <= 0 {
		opts.MaxHostCalls = defaultMaxHostCalls
	}
	return &SystemRunner{opts: opts, st: map[string]map[uint64]*systemPluginState{}, budgetWarnings: map[string]bool{}, startLocks: map[string]*sync.Mutex{}, draining: map[*systemPool]string{}}
}

func (r *SystemRunner) Name() string { return "system" }

// Start re-verifies the manifest-pinned digest of the artifact at the FIXED
// bundle path (TOCTOU defense in case the bundle changed after load), copies the
// bytes into a confined per-plugin 0700 working dir, and arms the runner. It
// always executes the staged 0700 copy, never the (possibly read-only or
// swapped) bundle file, and never resolves a manifest-controlled path.
func (r *SystemRunner) Start(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	result, err := r.Prepare(ctx, req)
	if err != nil {
		return result, err
	}
	if err := r.ActivateGeneration(req.PluginID, req.Generation); err != nil {
		_ = r.AbortGeneration(context.Background(), req.PluginID, req.Generation)
		return RunnerStartResult{}, err
	}
	return result, nil
}

// Prepare stages and starts an exact generation without admitting invocations.
func (r *SystemRunner) Prepare(ctx context.Context, req RunnerStartRequest) (RunnerStartResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
	isV2 := req.Loaded.Manifest.Runtime != nil && req.Loaded.Manifest.Runtime.Protocol == RuntimeProtocolStdioJSONV2
	if isV2 && req.Generation == 0 {
		return RunnerStartResult{}, fmt.Errorf("invalid stdio-json-v2 generation 0")
	}
	startLock := r.startLock(pluginID)
	if r.beforeStartLock != nil {
		r.beforeStartLock()
	}
	startLock.Lock()
	defer startLock.Unlock()
	if err := ctx.Err(); err != nil {
		return RunnerStartResult{}, err
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return RunnerStartResult{}, errors.New("system runner is closed")
	}
	oldAtPrepare := r.latestStateLocked(pluginID)
	if req.Generation != 0 && oldAtPrepare != nil && req.Generation <= oldAtPrepare.generation {
		r.mu.Unlock()
		return RunnerStartResult{}, fmt.Errorf("stale system runner generation %d; current is %d", req.Generation, oldAtPrepare.generation)
	}
	r.mu.Unlock()

	data, err := r.verifiedRuntimeBytes(req.Loaded)
	if err != nil {
		return RunnerStartResult{}, err
	}

	workDir := filepath.Join(r.opts.RuntimeDir, pluginID, fmt.Sprintf("generation-%d", req.Generation))
	if req.Generation == 0 {
		workDir = filepath.Join(r.opts.RuntimeDir, pluginID)
	}
	committed := false
	if req.Generation != 0 {
		defer func() {
			if !committed {
				_ = os.RemoveAll(workDir)
			}
		}()
	}
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

	pool := newSystemPool(256, time.Hour, req.Generation)
	pool.failureFn = func(generation uint64) { r.recordGenerationFailure(pluginID, generation) }
	pool.successFn = func(generation uint64) { r.recordGenerationSuccess(pluginID, generation) }
	if isV2 {
		pool.replenishFn = func(parent context.Context, gen uint64) (*pooledWorker, error) {
			ctx, cancel := context.WithTimeout(parent, 15*time.Second)
			defer cancel()
			t, err := startSystemWorker(ctx, execPath, workDir, r.v2ChildEnv(gen))
			if err != nil {
				return nil, err
			}
			if err := t.awaitReadyContext(ctx, gen); err != nil {
				_ = t.abort()
				return nil, err
			}
			return &pooledWorker{generation: gen, started: time.Now(), transport: t}, nil
		}
		startupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		transport, startErr := startSystemWorker(startupCtx, execPath, workDir, r.v2ChildEnv(req.Generation))
		if startErr == nil {
			startErr = transport.awaitReadyContext(startupCtx, req.Generation)
		}
		cancel()
		if startErr != nil {
			if transport != nil {
				_ = transport.abort()
			}
			return RunnerStartResult{}, fmt.Errorf("start v2 worker: %w", startErr)
		}
		if err := pool.publishTransport(req.Generation, transport, time.Now()); err != nil {
			_ = transport.abort()
			return RunnerStartResult{}, err
		}
	}
	r.mu.Lock()
	old := r.latestStateLocked(pluginID)
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		pool.abortClose(req.Generation)
		_ = os.RemoveAll(workDir)
		return RunnerStartResult{}, err
	}
	if r.closing {
		r.mu.Unlock()
		pool.abortClose(req.Generation)
		_ = os.RemoveAll(workDir)
		return RunnerStartResult{}, errors.New("system runner is closed")
	}
	if old != nil && (isV2 || req.Generation != 0) && req.Generation <= old.generation {
		r.mu.Unlock()
		pool.abortClose(req.Generation)
		_ = os.RemoveAll(workDir)
		return RunnerStartResult{}, fmt.Errorf("stale system runner generation %d; current is %d", req.Generation, old.generation)
	}
	byGeneration := r.st[pluginID]
	if byGeneration == nil {
		byGeneration = map[uint64]*systemPluginState{}
		r.st[pluginID] = byGeneration
	}
	rootCtx, rootCancel := context.WithCancel(context.Background())
	byGeneration[req.Generation] = &systemPluginState{execPath: execPath, workDir: workDir, broker: req.Broker, pool: pool, isV2: isV2, generation: req.Generation, cleanupDone: make(chan struct{}), v1Active: map[uint64]context.CancelFunc{}, rootCtx: rootCtx, rootCancel: rootCancel}
	committed = true
	r.mu.Unlock()
	return RunnerStartResult{Message: "system runner armed (subprocess execution enabled)"}, nil
}

func (r *SystemRunner) latestStateLocked(pluginID string) *systemPluginState {
	var latest *systemPluginState
	for _, st := range r.st[pluginID] {
		if latest == nil || st.generation > latest.generation {
			latest = st
		}
	}
	return latest
}

func (r *SystemRunner) ActivateGeneration(pluginID string, generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return errors.New("system runner is closed")
	}
	st := r.st[pluginID][generation]
	if st == nil || st.retiring {
		return fmt.Errorf("system runner generation %d is not prepared", generation)
	}
	st.admitted = true
	return nil
}

func (r *SystemRunner) AbortGeneration(ctx context.Context, pluginID string, generation uint64) error {
	r.mu.Lock()
	st := r.st[pluginID][generation]
	if st != nil {
		delete(r.st[pluginID], generation)
		if len(r.st[pluginID]) == 0 {
			delete(r.st, pluginID)
		}
	}
	r.mu.Unlock()
	if st != nil {
		if st.pool != nil {
			st.pool.abortClose(st.generation)
		}
		_ = os.RemoveAll(st.workDir)
	}
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

func (r *SystemRunner) RetireGeneration(ctx context.Context, pluginID string, generation uint64) error {
	r.mu.Lock()
	st := r.st[pluginID][generation]
	if st == nil {
		r.mu.Unlock()
		return nil
	}
	st.admitted = false
	st.retiring = true
	r.maybeStartCleanupLocked(st)
	r.mu.Unlock()
	return nil
}

func (r *SystemRunner) maybeStartCleanupLocked(st *systemPluginState) {
	// Forced retirement cancels/aborts the generation immediately, but cleanup
	// ownership remains pinned until every acquired invocation releases. This
	// keeps workdir removal and cleanupDone behind v1 Cmd.Wait/process reaping.
	if !st.retiring || st.refs != 0 {
		return
	}
	st.cleanupOnce.Do(func() {
		go r.cleanupGeneration("", st.generation, st)
	})
}

func (r *SystemRunner) cleanupGeneration(pluginID string, generation uint64, st *systemPluginState) {
	if st.broker != nil && st.broker.authority != nil {
		st.broker.authority.revoke()
		_ = st.broker.authority.wait(context.Background())
	}
	if st.pool != nil {
		r.mu.Lock()
		forceAbort := st.forceAbort
		r.mu.Unlock()
		if forceAbort {
			st.pool.abortClose(st.generation)
		} else {
			<-st.pool.gracefulDrain(st.generation)
		}
	}
	_ = os.RemoveAll(st.workDir)
	r.mu.Lock()
	for id, generations := range r.st {
		if generations[generation] == st {
			delete(generations, generation)
			if len(generations) == 0 {
				delete(r.st, id)
			}
			break
		}
	}
	close(st.cleanupDone)
	r.mu.Unlock()
}

func (r *SystemRunner) startLock(pluginID string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	lock := r.startLocks[pluginID]
	if lock == nil {
		lock = &sync.Mutex{}
		r.startLocks[pluginID] = lock
	}
	return lock
}

func (r *SystemRunner) verifiedRuntimeBytes(loaded Loaded) ([]byte, error) {
	if loaded.Manifest.Schema != ManifestSchemaV2 {
		artifactPath := loaded.ArtifactPath
		if artifactPath == "" {
			artifactPath = filepath.Join(loaded.BundlePath, artifactFileName)
		}
		data, err := os.ReadFile(artifactPath)
		if err != nil {
			return nil, fmt.Errorf("read artifact: %w", err)
		}
		if loaded.Manifest.DigestSHA256 != "" {
			if err := verifyDigest(loaded.Manifest.DigestSHA256, data); err != nil {
				return nil, fmt.Errorf("artifact digest mismatch at start: %w", err)
			}
		}
		return data, nil
	}
	if loaded.Manifest.Bundle == nil || loaded.ArtifactDigest != loaded.Manifest.Bundle.DigestSHA256 {
		return nil, errors.New("v2 loaded bundle digest metadata is inconsistent")
	}
	artifactPath := loaded.ArtifactPath
	if artifactPath == "" {
		artifactPath = filepath.Join(loaded.BundlePath, artifactFileName)
	}
	limit := normalizedBundleLimits(loaded.BundleLimits).MaxCompressedBytes
	archive, err := readBoundedRegularFile(artifactPath, limit)
	if err != nil {
		return nil, fmt.Errorf("read v2 bundle artifact: %w", err)
	}
	if err := verifyDigest(loaded.Manifest.Bundle.DigestSHA256, archive); err != nil {
		return nil, fmt.Errorf("v2 bundle digest mismatch at start: %w", err)
	}
	if loaded.ExtractedRoot == "" || loaded.RuntimeEntry == "" || loaded.RuntimePath == "" {
		return nil, errors.New("v2 loaded plugin has no selected runtime metadata")
	}
	if !safeBundlePath(loaded.RuntimeEntry) {
		return nil, errors.New("v2 loaded plugin has invalid runtime entry")
	}
	wantPath := filepath.Join(loaded.ExtractedRoot, filepath.FromSlash(loaded.RuntimeEntry))
	if filepath.Clean(loaded.RuntimePath) != filepath.Clean(wantPath) {
		return nil, errors.New("v2 runtime path does not match extracted root and entry")
	}
	want, ok := loaded.Inventory[loaded.RuntimeEntry]
	if !ok {
		return nil, errors.New("v2 runtime is missing from verified inventory")
	}
	if err := validateRuntimePath(loaded.ExtractedRoot, loaded.RuntimePath, os.FileMode(want.Mode)); err != nil {
		return nil, fmt.Errorf("v2 runtime metadata validation failed: %w", err)
	}
	data, err := os.ReadFile(loaded.RuntimePath)
	if err != nil {
		return nil, fmt.Errorf("read v2 runtime: %w", err)
	}
	if int64(len(data)) != want.Size || DigestSHA256(data) != want.SHA256 {
		return nil, errors.New("v2 runtime size or digest differs from verified inventory")
	}
	return data, nil
}

func validateRuntimePath(root, runtimePath string, wantMode os.FileMode) error {
	root = filepath.Clean(root)
	runtimePath = filepath.Clean(runtimePath)
	rel, err := filepath.Rel(root, runtimePath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("runtime path escapes extracted root")
	}
	current := root
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
		if i < len(parts)-1 {
			if !info.IsDir() || info.Mode().Perm() != 0o700 {
				return fmt.Errorf("path component %q is not a secure directory", current)
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != wantMode.Perm() {
			return fmt.Errorf("runtime %q is not a regular file with mode %o", current, wantMode.Perm())
		}
	}
	return nil
}

// Stop clears the plugin's staged state and removes its runtime dir. In-flight
// invocations are bound to their own context and terminate independently.
func (r *SystemRunner) Stop(ctx context.Context, req RunnerStopRequest) error {
	r.mu.Lock()
	var states []*systemPluginState
	var v1Cancels []context.CancelFunc
	for generation, st := range r.st[req.PluginID] {
		if req.Generation == 0 || generation <= req.Generation {
			st.admitted = false
			st.retiring = true
			st.forceAbort = true
			if st.rootCancel != nil {
				st.rootCancel()
			}
			states = append(states, st)
			for _, cancel := range st.v1Active {
				v1Cancels = append(v1Cancels, cancel)
			}
			r.maybeStartCleanupLocked(st)
		}
	}
	r.mu.Unlock()
	for _, st := range states {
		if st.broker != nil && st.broker.authority != nil {
			st.broker.authority.revoke()
		}
		if st.pool != nil {
			st.pool.abortClose(st.generation)
		}
	}
	for _, cancel := range v1Cancels {
		cancel()
	}
	for _, st := range states {
		if ctx == nil {
			<-st.cleanupDone
			continue
		}
		select {
		case <-st.cleanupDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// StopAll drains every generation and reaps all persistent workers during
// graceful server shutdown.
func (r *SystemRunner) StopAll(ctx context.Context) error {
	r.mu.Lock()
	r.closing = true
	var states []*systemPluginState
	var v1Cancels []context.CancelFunc
	for _, generations := range r.st {
		for _, st := range generations {
			st.admitted = false
			st.retiring = true
			st.forceAbort = true
			if st.rootCancel != nil {
				st.rootCancel()
			}
			states = append(states, st)
			for _, cancel := range st.v1Active {
				v1Cancels = append(v1Cancels, cancel)
			}
			r.maybeStartCleanupLocked(st)
		}
	}
	r.mu.Unlock()
	for _, st := range states {
		if st.broker != nil && st.broker.authority != nil {
			st.broker.authority.revoke()
		}
		if st.pool != nil {
			st.pool.abortClose(st.generation)
		}
	}
	for _, cancel := range v1Cancels {
		cancel()
	}
	for _, st := range states {
		if ctx == nil {
			<-st.cleanupDone
			continue
		}
		select {
		case <-st.cleanupDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Invoke runs the plugin for one action and returns its decoded reply. The
// process is spawned with arg-vector exec (NO shell, so payload content can never
// be interpreted as a command), a confined working directory, an allowlisted
// environment, capped output, and a deadline that escalates SIGTERM->SIGKILL.
// Repeated failures trip the circuit breaker. A crashing plugin yields an error,
// never a host crash.
type systemInvocationLease struct {
	runner *SystemRunner
	state  *systemPluginState
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (r *SystemRunner) AcquireInvocation(pluginID string, generation uint64) (InvocationGenerationLease, error) {
	r.mu.Lock()
	st := r.st[pluginID][generation]
	if st == nil || !st.admitted || st.retiring || r.closing {
		r.mu.Unlock()
		return nil, fmt.Errorf("plugin %q generation %d is not admitted", pluginID, generation)
	}
	st.refs++
	if st.rootCtx == nil {
		st.rootCtx, st.rootCancel = context.WithCancel(context.Background())
	}
	leaseCtx, leaseCancel := context.WithCancel(st.rootCtx)
	r.mu.Unlock()
	return &systemInvocationLease{runner: r, state: st, ctx: leaseCtx, cancel: leaseCancel}, nil
}

func (l *systemInvocationLease) Invoke(ctx context.Context, req InvokeRequest) (InvokeResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return InvokeResponse{}, err
	}
	if err := l.ctx.Err(); err != nil {
		return InvokeResponse{}, err
	}
	invokeCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(l.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := invokeCtx.Err(); err != nil {
		return InvokeResponse{}, err
	}
	return l.runner.invokeState(invokeCtx, req, l.state)
}

func (l *systemInvocationLease) Release() {
	l.once.Do(func() {
		l.cancel()
		r := l.runner
		r.mu.Lock()
		l.state.refs--
		if l.state.refs < 0 {
			panic("system runner invocation reference underflow")
		}
		r.maybeStartCleanupLocked(l.state)
		r.mu.Unlock()
	})
}

func (r *SystemRunner) Invoke(ctx context.Context, req InvokeRequest) (InvokeResponse, error) {
	lease, err := r.AcquireInvocation(req.PluginID, req.Generation)
	if err != nil {
		return InvokeResponse{}, err
	}
	defer lease.Release()
	return lease.Invoke(ctx, req)
}

func (r *SystemRunner) invokeState(ctx context.Context, req InvokeRequest, st *systemPluginState) (InvokeResponse, error) {
	r.mu.Lock()
	tripped := st != nil && st.tripped
	execPath, workDir := "", ""
	var broker *Broker
	if st != nil {
		execPath, workDir = st.execPath, st.workDir
		broker = st.broker
	}
	r.mu.Unlock()
	if st.isV2 && req.Generation == 0 {
		return InvokeResponse{}, fmt.Errorf("invalid stdio-json-v2 generation 0")
	}
	if req.Generation != st.generation {
		return InvokeResponse{}, fmt.Errorf("stale plugin generation: got %d want %d", req.Generation, st.generation)
	}
	if tripped {
		return InvokeResponse{}, fmt.Errorf("%w: %s", ErrCircuitOpen, req.PluginID)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	budget, err := r.invokeBudget(req)
	if err != nil {
		return InvokeResponse{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, budget.Timeout)
	defer cancel()
	runCtx, err = BindOperatorTargets(runCtx, req.Constraints.OperatorTargets)
	if err != nil {
		return InvokeResponse{}, err
	}
	runCtx, err = BindOperation(runCtx, req.Constraints.Operation)
	if err != nil {
		return InvokeResponse{}, err
	}
	if st.isV2 {
		w, err := st.pool.checkout(runCtx, time.Now())
		if err != nil {
			return InvokeResponse{}, err
		}
		invocation := fmt.Sprintf("%d", time.Now().UnixNano())
		outcome, callErr := w.transport.invokeV2(runCtx, req.Generation, invocation, req, func(call systemHostCall) systemHostResponse { return r.handleHostCall(runCtx, broker, call) }, budget)
		if callErr != nil {
			if !outcome.DispatchStarted && (errors.Is(callErr, context.Canceled) || errors.Is(callErr, context.DeadlineExceeded)) {
				st.pool.returnUnused(w, time.Now())
				return InvokeResponse{}, callErr
			}
			if ctx.Err() == nil {
				r.recordLifecycleFailure(req.PluginID, st)
			}
			st.pool.poison(w)
			warnings := v2StderrWarnings(budget, outcome.StderrTruncated)
			if len(outcome.Stderr) > 0 {
				r.logf("plugin runtime: transport failure for %s stderr_bytes=%d stderr_truncated=%t", req.PluginID, len(outcome.Stderr), outcome.StderrTruncated)
			}
			return InvokeResponse{Warnings: warnings}, fmt.Errorf("plugin %q transport failure: %w", req.PluginID, callErr)
		}
		reply := outcome.Reply
		warnings := append([]string(nil), reply.Warnings...)
		warnings = append(warnings, v2StderrWarnings(budget, outcome.StderrTruncated)...)
		if outcome.Retirement != nil {
			if ctx.Err() == nil {
				r.recordLifecycleFailure(req.PluginID, st)
			}
			st.pool.poison(w)
			warning := "persistent worker retired after terminal protocol failure"
			warnings = append(warnings, warning)
			r.logf("plugin runtime: %s %s: %v", warning, req.PluginID, outcome.Retirement)
		} else if outcome.Reusable {
			st.pool.release(w, outcome.ResultSeen, time.Now())
			r.recordLifecycleSuccess(req.PluginID, st)
		} else {
			st.pool.poison(w)
			return InvokeResponse{}, fmt.Errorf("plugin %q invocation completed without reusable terminal state", req.PluginID)
		}
		result := reply.Result
		if len(result) == 0 {
			result = reply.Plan
		}
		if !reply.OK {
			msg := reply.Message
			if msg == "" {
				msg = reply.Error
			}
			return InvokeResponse{OK: false, Message: msg, Result: result, Warnings: warnings}, fmt.Errorf("plugin %q reported failure: %s", req.PluginID, msg)
		}
		return InvokeResponse{OK: true, Message: reply.Message, Result: result, Warnings: warnings}, nil
	}

	// The approved operation's authority is bound before protocol selection.
	r.mu.Lock()
	st.v1Next++
	v1ID := st.v1Next
	v1Ctx, v1Cancel := context.WithCancel(runCtx)
	st.v1Active[v1ID] = v1Cancel
	r.mu.Unlock()
	reply, stderr, stderrTruncated, runErr := r.runInvocation(v1Ctx, req, execPath, workDir, broker, budget)
	v1Cancel()
	r.mu.Lock()
	delete(st.v1Active, v1ID)
	r.mu.Unlock()
	if runErr != nil {
		if ctx.Err() == nil {
			r.recordLifecycleFailure(req.PluginID, st)
		}
		r.logf("plugin runtime: invocation failure for %s stderr_bytes=%d stderr_truncated=%t", req.PluginID, len(stderr), stderrTruncated)
		if ctxErr := runCtx.Err(); ctxErr != nil {
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				return InvokeResponse{}, fmt.Errorf("plugin %q invocation timed out after %s: %w", req.PluginID, budget.Timeout, ctxErr)
			}
			return InvokeResponse{}, fmt.Errorf("plugin %q invocation canceled: %w", req.PluginID, ctxErr)
		}
		return InvokeResponse{}, fmt.Errorf("plugin %q invocation failed: %w", req.PluginID, runErr)
	}
	result := reply.Result
	if len(result) == 0 {
		result = reply.Plan // tolerate the bootstrap template's {"plan":...} shape
	}
	r.recordLifecycleSuccess(req.PluginID, st)
	var warnings []string
	if reply.TeardownWarning != "" {
		warnings = append(warnings, reply.TeardownWarning)
		r.logf("plugin runtime: %s for %s", reply.TeardownWarning, req.PluginID)
	}
	if stderrTruncated {
		warning := fmt.Sprintf("stderr truncated after %d bytes", budget.StderrBytes)
		warnings = append(warnings, warning)
		r.logf("plugin runtime: %s for %s %s", warning, req.PluginID, budgetLogLabel(req))
	}
	if !reply.OK {
		msg := reply.Message
		if msg == "" {
			msg = reply.Error
		}
		return InvokeResponse{OK: false, Message: msg, Result: result, Warnings: warnings},
			fmt.Errorf("plugin %q reported failure: %s", req.PluginID, msg)
	}
	return InvokeResponse{OK: true, Message: reply.Message, Result: result, Warnings: warnings}, nil
}

func v2StderrWarnings(budget ResolvedInvokeBudget, truncated bool) []string {
	if !truncated {
		return nil
	}
	return []string{fmt.Sprintf("stderr truncated after %d bytes", budget.StderrBytes)}
}

type systemRunnerReply struct {
	OK              bool            `json:"ok"`
	Message         string          `json:"message"`
	Result          json.RawMessage `json:"result"`
	Plan            json.RawMessage `json:"plan"`
	Error           string          `json:"error"`
	Warnings        []string        `json:"warnings"`
	TeardownWarning string          `json:"-"`
}

type systemHostCall struct {
	ID     string          `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type systemHostResponseEnvelope struct {
	HostResponse systemHostResponse `json:"host_response"`
}

type systemHostResponse struct {
	ID     string          `json:"id,omitempty"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func (r *SystemRunner) runInvocation(ctx context.Context, req InvokeRequest, execPath, workDir string, broker *Broker, budget ResolvedInvokeBudget) (systemRunnerReply, []byte, bool, error) {
	cmd := exec.Command(execPath)
	cmd.Dir = workDir
	cmd.Env = append(r.childEnv(), "LATTICE_HOST_RESPONSE_FD=3")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	hostRespR, hostRespW, err := os.Pipe()
	if err != nil {
		return systemRunnerReply{}, nil, false, fmt.Errorf("open host response pipe: %w", err)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, hostRespR)

	stdinR, stdin, err := os.Pipe()
	if err != nil {
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, nil, false, fmt.Errorf("open stdin: %w", err)
	}
	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdin.Close()
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, nil, false, fmt.Errorf("open stdout: %w", err)
	}
	stderrPipe, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stdoutW.Close()
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, nil, false, fmt.Errorf("open stderr: %w", err)
	}
	stderr := &cappedBuffer{limit: budget.StderrBytes}
	stderrDone := make(chan struct{})
	waitDone := make(chan struct{})
	var waitErr error
	var groupOnce sync.Once
	groupDone := make(chan struct{})
	var groupErr error
	startGroupReap := func() {
		groupOnce.Do(func() {
			go func() {
				groupErr = terminateProcessGroup(cmd.Process.Pid, r.opts.StopGrace)
				close(groupDone)
			}()
		})
	}
	wait := func() error {
		<-waitDone
		<-stderrDone
		return waitErr
	}
	abort := func(cause error) (systemRunnerReply, []byte, bool, error) {
		_ = stdin.Close()
		_ = hostRespW.Close()
		startGroupReap()
		<-groupDone
		_ = wait()
		_ = stdout.Close()
		return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), cause
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		_ = stdinR.Close()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stdoutW.Close()
		_ = stderrPipe.Close()
		_ = stderrW.Close()
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), fmt.Errorf("start artifact: %w", err)
	}
	_ = stdinR.Close()
	_ = stdoutW.Close()
	_ = stderrW.Close()
	_ = hostRespR.Close()
	defer stdout.Close()
	go func() {
		waitErr = cmd.Wait()
		close(waitDone)
	}()
	go func() {
		_, _ = io.Copy(stderr, stderrPipe)
		_ = stderrPipe.Close()
		close(stderrDone)
	}()
	monitorStop := make(chan struct{})
	monitorDone := make(chan struct{})
	var monitorStopOnce sync.Once
	stopMonitor := func() {
		monitorStopOnce.Do(func() { close(monitorStop) })
		<-monitorDone
	}
	defer stopMonitor()
	go func() {
		select {
		case <-ctx.Done():
			startGroupReap()
		case <-monitorStop:
		}
		close(monitorDone)
	}()

	enc := json.NewEncoder(stdin)
	hostEnc := json.NewEncoder(hostRespW)
	if err := enc.Encode(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{Action: req.Action, Payload: req.Payload}); err != nil {
		return abort(fmt.Errorf("write invoke request: %w", err))
	}
	_ = stdin.Close()

	scanner := bufio.NewScanner(stdout)
	scanner.Split(splitWireLines)
	scanner.Buffer(make([]byte, 0, min(64*1024, budget.StdoutBytes+1)), budget.StdoutBytes+1)
	hostCalls := 0
	stdoutConsumed := 0
	for scanner.Scan() {
		stdoutConsumed += len(scanner.Bytes())
		if stdoutConsumed > budget.StdoutBytes {
			return abort(fmt.Errorf("plugin exceeded cumulative stdout limit %d", budget.StdoutBytes))
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if call, ok, err := decodeSystemHostCall(line); err != nil {
			return abort(err)
		} else if ok {
			hostCalls++
			if hostCalls > budget.HostCalls {
				return abort(fmt.Errorf("plugin exceeded host-call limit %d", budget.HostCalls))
			}
			resp := r.handleHostCall(ctx, broker, call)
			if err := hostEnc.Encode(systemHostResponseEnvelope{HostResponse: resp}); err != nil {
				return abort(fmt.Errorf("write host response: %w", err))
			}
			continue
		}

		var reply systemRunnerReply
		if err := json.Unmarshal(line, &reply); err != nil {
			return abort(fmt.Errorf("decode plugin response: %w", err))
		}
		_ = hostRespW.Close()
		select {
		case <-waitDone:
		case <-ctx.Done():
			startGroupReap()
			<-groupDone
		}
		// A leader exit and the invocation deadline can become ready together.
		// Context cancellation wins: synchronize the monitor, reap the complete
		// group, and preserve errors.Is semantics instead of returning success.
		if ctxErr := ctx.Err(); ctxErr != nil {
			startGroupReap()
			<-groupDone
			_ = wait()
			return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), errors.Join(ctxErr, groupErr)
		}
		stopMonitor()
		if ctxErr := ctx.Err(); ctxErr != nil {
			startGroupReap()
			<-groupDone
			_ = wait()
			return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), errors.Join(ctxErr, groupErr)
		}
		if processGroupExists(cmd.Process.Pid) {
			startGroupReap()
			<-groupDone
			if groupErr != nil {
				return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), groupErr
			}
		}
		if werr := wait(); werr != nil {
			if err := ctx.Err(); err != nil {
				return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), err
			}
			// The plugin already produced a valid terminal reply. A non-zero exit
			// during teardown (e.g. a noisy cleanup deferred after the reply was
			// written) must NOT be treated as an invocation failure — doing so would
			// trip the circuit breaker against an otherwise-correct plugin and
			// silently disable it (design-12 runtime review HIGH-1). Surface only
			// stable exit metadata and return the valid reply so the breaker does
			// not trip or expose raw stderr.
			reply.TeardownWarning = fmt.Sprintf("plugin exited non-zero after terminal result: %v", werr)
		}
		return reply, stderr.Bytes(), stderr.Truncated(), nil
	}
	if err := scanner.Err(); err != nil {
		if strings.Contains(err.Error(), "token too long") {
			return abort(fmt.Errorf("plugin stdout exceeded budget %d bytes", budget.StdoutBytes))
		}
		return abort(fmt.Errorf("read plugin stdout: %w", err))
	}
	_ = hostRespW.Close()
	if ctx.Err() != nil {
		startGroupReap()
		<-groupDone
	}
	if err := wait(); err != nil {
		return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), err
	}
	return systemRunnerReply{}, stderr.Bytes(), stderr.Truncated(), errors.New("plugin exited without a response")
}

// splitWireLines preserves the exact bytes consumed from the pipe, including
// LF/CRLF delimiters and a final unterminated frame. Invocation budgets apply
// to the raw wire rather than ScanLines-normalized tokens.
func splitWireLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i+1], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func processGroupExists(pgid int) bool {
	if pgid <= 0 {
		return false
	}
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// terminateProcessGroup owns the complete TERM-to-KILL escalation for one
// process group. Leader exit is not completion: descendants may inherit the
// runtime pipes and ignore TERM, so the group must become extinct before the
// transport or one-shot invocation is considered reaped.
func terminateProcessGroup(pgid int, grace time.Duration) error {
	if !processGroupExists(pgid) {
		return nil
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	deadline := time.NewTimer(grace)
	tick := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()
	for processGroupExists(pgid) {
		select {
		case <-deadline.C:
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			// StopGrace controls only the cooperative TERM window. Kernel/process
			// scheduler latency after SIGKILL is a separate concern and must not
			// collapse to a test-sized (e.g. 10ms) grace, otherwise an extinct
			// group can be reported as live and a valid terminal result discarded.
			killDeadline := time.NewTimer(postKillReapAllowance)
			defer killDeadline.Stop()
			for processGroupExists(pgid) {
				select {
				case <-killDeadline.C:
					return fmt.Errorf("process group %d survived SIGKILL", pgid)
				case <-tick.C:
				}
			}
			return nil
		case <-tick.C:
		}
	}
	return nil
}

func (r *SystemRunner) invokeBudget(req InvokeRequest) (ResolvedInvokeBudget, error) {
	defaults := InvokeBudgetSpec{
		TimeoutMS:   int(r.opts.InvokeTimeout / time.Millisecond),
		StdoutBytes: r.opts.MaxOutputBytes,
		StderrBytes: r.opts.MaxOutputBytes,
		HostCalls:   r.opts.MaxHostCalls,
	}
	if req.Constraints.Budget != nil {
		if err := validateInvokeBudgetPositive(*req.Constraints.Budget); err != nil {
			return ResolvedInvokeBudget{}, fmt.Errorf("invoke budget: %w", err)
		}
	}
	budget := ResolveInvokeBudget(req.Constraints.Budget, defaults)
	if !budget.Declared {
		r.warnDefaultBudgetOnce(req, budget)
	}
	return budget, nil
}

func (r *SystemRunner) warnDefaultBudgetOnce(req InvokeRequest, budget ResolvedInvokeBudget) {
	if r.opts.Logf == nil {
		return
	}
	label := budgetLogLabel(req)
	key := req.PluginID + "\x00" + label
	r.mu.Lock()
	if r.budgetWarnings[key] {
		r.mu.Unlock()
		return
	}
	r.budgetWarnings[key] = true
	r.mu.Unlock()
	r.logf("plugin runtime: %s %s has no declared budget; using defaults timeout=%s stdout_bytes=%d stderr_bytes=%d host_calls=%d",
		req.PluginID, label, budget.Timeout, budget.StdoutBytes, budget.StderrBytes, budget.HostCalls)
}

func (r *SystemRunner) logf(format string, args ...any) {
	if r.opts.Logf != nil {
		r.opts.Logf(format, args...)
	}
}

func budgetLogLabel(req InvokeRequest) string {
	if req.Constraints.BudgetLabel != "" {
		return req.Constraints.BudgetLabel
	}
	if req.Action != "" {
		return req.Action
	}
	return "invoke"
}

func decodeSystemHostCall(line []byte) (systemHostCall, bool, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(line, &envelope); err != nil {
		return systemHostCall{}, false, nil
	}
	raw, ok := envelope["host_call"]
	if !ok {
		return systemHostCall{}, false, nil
	}
	var call systemHostCall
	if err := json.Unmarshal(raw, &call); err != nil {
		return systemHostCall{}, false, fmt.Errorf("decode host_call: %w", err)
	}
	if call.Method == "" {
		return systemHostCall{}, false, errors.New("host_call method is required")
	}
	return call, true, nil
}

func signalProcessGroup(proc *os.Process, sig syscall.Signal) error {
	if proc == nil {
		return nil
	}
	if err := syscall.Kill(-proc.Pid, sig); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return proc.Signal(sig)
	}
	return nil
}

func (r *SystemRunner) handleHostCall(ctx context.Context, broker *Broker, call systemHostCall) systemHostResponse {
	result, err := dispatchHostCall(ctx, broker, call)
	if err != nil {
		return systemHostResponse{ID: call.ID, OK: false, Error: err.Error()}
	}
	return systemHostResponse{ID: call.ID, OK: true, Result: result}
}

func dispatchHostCall(ctx context.Context, broker *Broker, call systemHostCall) (json.RawMessage, error) {
	if broker == nil {
		return nil, errors.New("plugin broker unavailable")
	}
	authorityCtx, release, err := broker.acquireAuthority(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx = authorityCtx
	switch call.Method {
	case "rpc.call":
		var req struct {
			Service string          `json:"service"`
			Method  string          `json:"method"`
			Request json.RawMessage `json:"request,omitempty"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("rpc.call params: %w", err)
		}
		return broker.RPCCall(ctx, req.Service, req.Method, req.Request)
	case "http.do", "http.operator.do":
		var req struct {
			Method     string            `json:"method,omitempty"`
			URL        string            `json:"url"`
			Header     map[string]string `json:"header,omitempty"`
			Body       string            `json:"body,omitempty"`
			BodyBase64 string            `json:"body_base64,omitempty"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("%s params: %w", call.Method, err)
		}
		body := []byte(req.Body)
		if req.BodyBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(req.BodyBase64)
			if err != nil {
				return nil, fmt.Errorf("%s body_base64: %w", call.Method, err)
			}
			body = decoded
		}
		hostReq := HostHTTPRequest{Method: req.Method, URL: req.URL, Header: req.Header, Body: body}
		var resp HostHTTPResponse
		var err error
		if call.Method == "http.operator.do" {
			resp, err = broker.HTTPOperatorDo(ctx, hostReq)
		} else {
			resp, err = broker.HTTPDo(ctx, hostReq)
		}
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			StatusCode int               `json:"status_code"`
			Header     map[string]string `json:"header,omitempty"`
			BodyBase64 string            `json:"body_base64,omitempty"`
		}{StatusCode: resp.StatusCode, Header: resp.Header, BodyBase64: base64.StdEncoding.EncodeToString(resp.Body)})
	case "kv.get":
		var req struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("kv.get params: %w", err)
		}
		value, ok, err := broker.KVGet(ctx, req.Key)
		if err != nil {
			return nil, err
		}
		// The response rides one stdout-ish frame that the plugin scans with a
		// 1 MiB cap (sdk DefaultMaxHostResponseBytes). Sending the value twice —
		// raw AND base64 — doubles the frame, and any value past ~430 KiB kills
		// the plugin mid-invocation (runner sees a broken pipe). The SDK reader
		// prefers value_base64 whenever it is present, so past a small debug
		// threshold the raw duplicate is dropped. (2026-08-11: every plugin call
		// 502'd once the sub-store store grew past it.)
		resp := struct {
			OK          bool   `json:"ok"`
			Value       string `json:"value,omitempty"`
			ValueBase64 string `json:"value_base64,omitempty"`
		}{OK: ok, ValueBase64: base64.StdEncoding.EncodeToString(value)}
		if len(value) <= 64<<10 {
			resp.Value = string(value)
		}
		return json.Marshal(resp)
	case "kv.put":
		var req struct {
			Key         string `json:"key"`
			Value       string `json:"value,omitempty"`
			ValueBase64 string `json:"value_base64,omitempty"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("kv.put params: %w", err)
		}
		value := []byte(req.Value)
		if req.ValueBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(req.ValueBase64)
			if err != nil {
				return nil, fmt.Errorf("kv.put value_base64: %w", err)
			}
			value = decoded
		}
		if err := broker.KVPut(ctx, req.Key, value); err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), nil
	case "task.enqueue":
		var req struct {
			NodeID      string `json:"node_id"`
			Interpreter string `json:"interpreter"`
			Script      string `json:"script"`
			TimeoutSec  int    `json:"timeout_sec"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("task.enqueue params: %w", err)
		}
		taskID, err := broker.TaskEnqueue(ctx, HostTaskRequest{
			NodeID:      req.NodeID,
			Interpreter: req.Interpreter,
			Script:      req.Script,
			TimeoutSec:  req.TimeoutSec,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			TaskID string `json:"task_id"`
		}{TaskID: taskID})
	case "secret.get":
		var req struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("secret.get params: %w", err)
		}
		value, ok, err := broker.SecretGet(ctx, req.Key)
		if err != nil {
			return nil, err
		}
		// Base64 only. kv.get returns the raw string alongside the encoded one, and a
		// raw secret field is exactly what gets accidentally %v-logged or folded into
		// an error message somewhere downstream. One encoding, and it is not readable
		// by eye.
		return json.Marshal(struct {
			OK          bool   `json:"ok"`
			ValueBase64 string `json:"value_base64,omitempty"`
		}{OK: ok, ValueBase64: base64.StdEncoding.EncodeToString([]byte(value))})
	case "secret.put":
		var req struct {
			Key         string `json:"key"`
			ValueBase64 string `json:"value_base64"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("secret.put params: %w", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(req.ValueBase64)
		if err != nil {
			// Report the failure, never the payload that caused it.
			return nil, errors.New("secret.put value_base64 is not valid base64")
		}
		if err := broker.SecretPut(ctx, req.Key, string(decoded)); err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), nil
	case "secret.delete":
		var req struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("secret.delete params: %w", err)
		}
		if err := broker.SecretDelete(ctx, req.Key); err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), nil
	case "notify.send":
		var req struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("notify.send params: %w", err)
		}
		if err := broker.Notify(ctx, req.Title, req.Body); err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), nil
	case "log.write":
		var req struct {
			Level   string            `json:"level"`
			Message string            `json:"message"`
			Fields  map[string]string `json:"fields,omitempty"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("log.write params: %w", err)
		}
		if err := broker.Log(ctx, req.Level, req.Message, req.Fields); err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), nil
	default:
		return nil, fmt.Errorf("unsupported host_call method %q", call.Method)
	}
}

func (r *SystemRunner) recordLifecycleFailure(pluginID string, expected *systemPluginState) {
	r.mu.Lock()
	st := r.st[pluginID][expected.generation]
	if st == nil || st != expected {
		r.mu.Unlock()
		return
	}
	st.failures++
	if st.failures >= r.opts.CrashThreshold {
		st.tripped = true
	}
	tripped, pool := st.tripped, st.pool
	r.mu.Unlock()
	if tripped && pool != nil {
		pool.setCircuitOpen(true)
	}
}

func (r *SystemRunner) recordGenerationFailure(pluginID string, generation uint64) {
	r.mu.Lock()
	st := r.st[pluginID][generation]
	if st == nil {
		r.mu.Unlock()
		return
	}
	st.startupFailures++
	if st.startupFailures >= r.opts.CrashThreshold {
		st.tripped = true
	}
	tripped, pool := st.tripped, st.pool
	r.mu.Unlock()
	if tripped && pool != nil {
		pool.setCircuitOpen(true)
	}
}

func (r *SystemRunner) recordGenerationSuccess(pluginID string, generation uint64) {
	r.mu.Lock()
	if st := r.st[pluginID][generation]; st != nil {
		st.startupFailures = 0
	}
	r.mu.Unlock()
}

func (r *SystemRunner) recordLifecycleSuccess(pluginID string, expected *systemPluginState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.st[pluginID][expected.generation]; st != nil && st == expected {
		st.failures = 0
	}
}

// childEnv builds the allowlisted environment: only the named variables are
// forwarded, plus a fixed safe PATH unless PATH was itself allowlisted and set.
func (r *SystemRunner) childEnv() []string {
	env := make([]string, 0, len(r.opts.EnvAllowlist)+1)
	havePath := false
	for _, name := range r.opts.EnvAllowlist {
		if isReservedRuntimeEnv(name) {
			continue
		}
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

func isReservedRuntimeEnv(name string) bool {
	switch name {
	case "LATTICE_RUNTIME_PROTOCOL", "LATTICE_RUNTIME_GENERATION", "LATTICE_HOST_RESPONSE_FD":
		return true
	default:
		return false
	}
}

func (r *SystemRunner) v2ChildEnv(generation uint64) []string {
	return append(r.childEnv(),
		"LATTICE_RUNTIME_PROTOCOL="+RuntimeProtocolStdioJSONV2,
		"LATTICE_RUNTIME_GENERATION="+strconv.FormatUint(generation, 10),
		"LATTICE_HOST_RESPONSE_FD=3",
	)
}

// cappedBuffer stores at most limit bytes and silently discards the rest while
// still reporting full consumption, so the child's output pipe never blocks and
// host memory stays bounded.
type cappedBuffer struct {
	limit     int
	buf       bytes.Buffer
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room < len(p) {
		c.truncated = true
	}
	if room > 0 {
		if room > len(p) {
			room = len(p)
		}
		c.buf.Write(p[:room])
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

func (c *cappedBuffer) Truncated() bool { return c.truncated }

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
