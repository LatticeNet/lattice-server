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
	defaultInvokeTimeout  = 10 * time.Second
	defaultStopGrace      = 3 * time.Second
	defaultMaxOutputBytes = 1 << 20 // 1 MiB
	defaultCrashThreshold = 5
	defaultMaxHostCalls   = 64
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
}

type systemPluginState struct {
	execPath string
	workDir  string
	broker   *Broker
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
	if opts.MaxHostCalls <= 0 {
		opts.MaxHostCalls = defaultMaxHostCalls
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

	data, err := r.verifiedRuntimeBytes(req.Loaded)
	if err != nil {
		return RunnerStartResult{}, err
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
	r.st[pluginID] = &systemPluginState{execPath: execPath, workDir: workDir, broker: req.Broker}
	r.mu.Unlock()
	return RunnerStartResult{Message: "system runner armed (subprocess execution enabled)"}, nil
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
	var broker *Broker
	if st != nil {
		execPath, workDir = st.execPath, st.workDir
		broker = st.broker
	}
	r.mu.Unlock()
	if st == nil {
		return InvokeResponse{}, fmt.Errorf("plugin %q is not armed on the system runner", req.PluginID)
	}
	if tripped {
		return InvokeResponse{}, fmt.Errorf("%w: %s", ErrCircuitOpen, req.PluginID)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, r.opts.InvokeTimeout)
	defer cancel()
	runCtx, err := BindOperatorTargets(runCtx, req.Constraints.OperatorTargets)
	if err != nil {
		return InvokeResponse{}, fmt.Errorf("bind operator targets: %w", err)
	}

	reply, stderr, runErr := r.runInvocation(runCtx, req, execPath, workDir, broker)
	if runErr != nil {
		r.recordFailure(req.PluginID)
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return InvokeResponse{}, fmt.Errorf("plugin %q invocation timed out after %s", req.PluginID, r.opts.InvokeTimeout)
		}
		return InvokeResponse{}, fmt.Errorf("plugin %q invocation failed: %w (stderr: %s)", req.PluginID, runErr, truncForErr(stderr))
	}
	result := reply.Result
	if len(result) == 0 {
		result = reply.Plan // tolerate the bootstrap template's {"plan":...} shape
	}
	r.recordSuccess(req.PluginID)
	if !reply.OK {
		msg := reply.Message
		if msg == "" {
			msg = reply.Error
		}
		return InvokeResponse{OK: false, Message: msg, Result: result},
			fmt.Errorf("plugin %q reported failure: %s", req.PluginID, msg)
	}
	return InvokeResponse{OK: true, Message: reply.Message, Result: result}, nil
}

type systemRunnerReply struct {
	OK      bool            `json:"ok"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
	Plan    json.RawMessage `json:"plan"`
	Error   string          `json:"error"`
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

func (r *SystemRunner) runInvocation(ctx context.Context, req InvokeRequest, execPath, workDir string, broker *Broker) (systemRunnerReply, []byte, error) {
	cmd := exec.CommandContext(ctx, execPath)
	cmd.Dir = workDir
	cmd.Env = append(r.childEnv(), "LATTICE_HOST_RESPONSE_FD=3")
	// Graceful stop: send SIGTERM when ctx is done, then SIGKILL after grace.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return signalProcessGroup(cmd.Process, syscall.SIGTERM) }
	cmd.WaitDelay = r.opts.StopGrace

	hostRespR, hostRespW, err := os.Pipe()
	if err != nil {
		return systemRunnerReply{}, nil, fmt.Errorf("open host response pipe: %w", err)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, hostRespR)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, nil, fmt.Errorf("open stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, nil, fmt.Errorf("open stdout: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, nil, fmt.Errorf("open stderr: %w", err)
	}
	stderr := &cappedBuffer{limit: r.opts.MaxOutputBytes}
	stderrDone := make(chan struct{})

	waited := false
	wait := func() error {
		waited = true
		err := cmd.Wait()
		<-stderrDone
		return err
	}
	abort := func(cause error) (systemRunnerReply, []byte, error) {
		_ = stdin.Close()
		_ = hostRespW.Close()
		if cmd.Process != nil {
			_ = signalProcessGroup(cmd.Process, syscall.SIGKILL)
		}
		if !waited {
			_ = wait()
		}
		return systemRunnerReply{}, stderr.Bytes(), cause
	}

	if err := cmd.Start(); err != nil {
		_ = hostRespR.Close()
		_ = hostRespW.Close()
		return systemRunnerReply{}, stderr.Bytes(), fmt.Errorf("start artifact: %w", err)
	}
	_ = hostRespR.Close()
	go func() {
		_, _ = io.Copy(stderr, stderrPipe)
		close(stderrDone)
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
	scanner.Buffer(make([]byte, 0, 64*1024), r.opts.MaxOutputBytes)
	hostCalls := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if call, ok, err := decodeSystemHostCall(line); err != nil {
			return abort(err)
		} else if ok {
			hostCalls++
			if hostCalls > r.opts.MaxHostCalls {
				return abort(fmt.Errorf("plugin exceeded host-call limit %d", r.opts.MaxHostCalls))
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
		if werr := wait(); werr != nil {
			// The plugin already produced a valid terminal reply. A non-zero exit
			// during teardown (e.g. a noisy cleanup deferred after the reply was
			// written) must NOT be treated as an invocation failure — doing so would
			// trip the circuit breaker against an otherwise-correct plugin and
			// silently disable it (design-12 runtime review HIGH-1). Surface the
			// exit via stderr (which the caller already returns/logs) and return the
			// valid reply so the breaker does not trip.
			fmt.Fprintf(stderr, "\n[lattice] plugin %q exited non-zero after a valid reply: %v\n", req.PluginID, werr)
		}
		return reply, stderr.Bytes(), nil
	}
	if err := scanner.Err(); err != nil {
		return abort(fmt.Errorf("read plugin stdout: %w", err))
	}
	_ = hostRespW.Close()
	if err := wait(); err != nil {
		return systemRunnerReply{}, stderr.Bytes(), err
	}
	return systemRunnerReply{}, stderr.Bytes(), errors.New("plugin exited without a response")
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
		return json.Marshal(struct {
			OK          bool   `json:"ok"`
			Value       string `json:"value,omitempty"`
			ValueBase64 string `json:"value_base64,omitempty"`
		}{OK: ok, Value: string(value), ValueBase64: base64.StdEncoding.EncodeToString(value)})
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
