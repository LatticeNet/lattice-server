package plugin

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// stderr_chunk frames carry base64 data on the serialized stdout protocol.
// Their wire size is bounded independently from signed invocation stdout so a
// legitimate maximum diagnostics chunk can be parsed without spending that
// invocation's stdout allowance.
const maxV2WireFrameBytes = max(HostMaxInvokeStdoutBytes, (HostMaxInvokeStderrBytes*4+2)/3+64*1024)
const maxV2DiagnosticWireBytes = (HostMaxInvokeStderrBytes*4+2)/3 + 256*1024
const maxV2DiagnosticChunks = 1024

type transportFrame struct {
	line []byte
	err  error
}

func validateInvokeReady(f stdioJSONV2Frame, generation uint64, invocation string) error {
	if f.Protocol != 2 || f.Kind != "invoke_ready" || f.Generation != generation || f.InvocationID != invocation || f.HostCallID != "" || len(f.Request) != 0 || len(f.Response) != 0 || len(f.HostCall) != 0 || len(f.HostResponse) != 0 {
		return fmt.Errorf("invalid invoke_ready frame")
	}
	return nil
}

type v2InvokeOutcome struct {
	Reply           systemRunnerReply
	ResultSeen      bool
	Reusable        bool
	Retirement      error
	Stderr          []byte
	StderrTruncated bool
	DispatchStarted bool
}

func (t *systemWorkerTransport) invokeV2(ctx context.Context, generation uint64, invocation string, req InvokeRequest, host func(systemHostCall) systemHostResponse, budgets ...ResolvedInvokeBudget) (outcome v2InvokeOutcome, callErr error) {
	if err := ctx.Err(); err != nil {
		return outcome, err
	}
	if generation == 0 || !validSystemInvocationID(invocation) {
		return outcome, fmt.Errorf("invalid stdio invocation correlation")
	}
	if t == nil || t.stdin == nil || t.scanner == nil {
		return outcome, fmt.Errorf("worker transport unavailable")
	}
	frame := stdioJSONV2Frame{Protocol: 2, Kind: "invoke", Generation: generation, InvocationID: invocation}
	frame.Request, _ = json.Marshal(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{req.Action, req.Payload})
	stdoutLimit, hostCallLimit := HostMaxInvokeStdoutBytes, HostMaxInvokeHostCalls
	stderrLimit := HostMaxInvokeStderrBytes
	if len(budgets) > 0 {
		if budgets[0].StdoutBytes > 0 {
			stdoutLimit = budgets[0].StdoutBytes
		}
		hostCallLimit = budgets[0].HostCalls
		if budgets[0].StderrBytes > 0 {
			stderrLimit = budgets[0].StderrBytes
		}
	}
	diagnostics := &cappedBuffer{limit: stderrLimit}
	defer func() {
		outcome.Stderr, outcome.StderrTruncated = append([]byte(nil), diagnostics.Bytes()...), diagnostics.Truncated()
	}()
	write := make(chan error, 1)
	outcome.DispatchStarted = true
	go func() { write <- json.NewEncoder(t.stdin).Encode(frame) }()
	select {
	case err := <-write:
		if err != nil {
			return outcome, err
		}
	case <-ctx.Done():
		_ = t.abort()
		return outcome, ctx.Err()
	}
	seenHostCalls := make(map[string]struct{})
	stdoutConsumed := 0
	diagnosticWireConsumed := 0
	diagnosticChunks := 0
	diagnosticDecodedTotal := 0
	consumeFrame := func(line []byte) error {
		// Scanner strips the newline delimiter; count one byte per JSONL frame so
		// signed stdout_bytes enforcement matches bytes emitted on the wire.
		stdoutConsumed += len(line) + 1
		if stdoutConsumed > stdoutLimit {
			return fmt.Errorf("plugin exceeded stdout limit %d", stdoutLimit)
		}
		return nil
	}
	for {
		var line []byte
		fr, err := t.nextFrame(ctx)
		if err != nil {
			_ = t.abort()
			return outcome, err
		}
		line = fr
		f, err := decodeStdioJSONV2Frame(line, maxV2WireFrameBytes)
		if err != nil {
			return outcome, err
		}
		if err := validateStdioJSONV2Frame(f, generation, invocation, ""); err != nil {
			return outcome, err
		}
		if f.Kind != "stderr_chunk" {
			if err := consumeFrame(line); err != nil {
				return outcome, err
			}
		}
		if f.Kind == "host_call" {
			if host == nil || f.HostCallID == "" {
				return outcome, fmt.Errorf("invalid host call")
			}
			if _, duplicate := seenHostCalls[f.HostCallID]; duplicate {
				return outcome, fmt.Errorf("duplicate host_call_id %q", f.HostCallID)
			}
			if len(seenHostCalls) >= hostCallLimit {
				return outcome, fmt.Errorf("plugin exceeded host-call limit %d", hostCallLimit)
			}
			seenHostCalls[f.HostCallID] = struct{}{}
			call, err := decodeStrictSystemHostCall(f.HostCall, f.HostCallID, HostMaxInvokeStdoutBytes)
			if err != nil {
				return outcome, err
			}
			resp := host(call)
			writeResp := make(chan error, 1)
			go func() {
				writeResp <- emitBoundedHostResponse(t.hostResp, resp, buildV2HostResponseFrame(generation, invocation, f.HostCallID))
			}()
			select {
			case err := <-writeResp:
				if err != nil {
					return outcome, err
				}
			case <-ctx.Done():
				_ = t.abort()
				return outcome, ctx.Err()
			}
			continue
		}
		if f.Kind == "stderr_chunk" {
			diagnosticChunks++
			diagnosticWireConsumed += len(line) + 1
			if diagnosticChunks > maxV2DiagnosticChunks || diagnosticWireConsumed > maxV2DiagnosticWireBytes {
				return outcome, fmt.Errorf("plugin exceeded diagnostic frame limit")
			}
			if len(f.Data) > base64.StdEncoding.EncodedLen(HostMaxInvokeStderrBytes) {
				return outcome, fmt.Errorf("stderr_chunk exceeds host maximum")
			}
			chunk, err := base64.StdEncoding.DecodeString(f.Data)
			if err != nil {
				return outcome, fmt.Errorf("invalid stderr_chunk data")
			}
			if base64.StdEncoding.EncodeToString(chunk) != f.Data {
				return outcome, fmt.Errorf("non-canonical stderr_chunk data")
			}
			if len(chunk) > HostMaxInvokeStderrBytes-diagnosticDecodedTotal {
				return outcome, fmt.Errorf("plugin exceeded diagnostic decoded limit %d", HostMaxInvokeStderrBytes)
			}
			diagnosticDecodedTotal += len(chunk)
			_, _ = diagnostics.Write(chunk)
			continue
		}
		if f.Kind == "invoke_ready" {
			return outcome, fmt.Errorf("invoke_ready before result")
		}
		if f.Kind != "invoke_result" {
			return outcome, fmt.Errorf("unexpected v2 frame %q", f.Kind)
		}
		reply, err := decodeSystemRunnerReply(f.Response, HostMaxInvokeStdoutBytes)
		if err != nil {
			return outcome, err
		}
		if f.Kind == "invoke_result" {
			for {
				var err error
				line, err = t.nextFrame(ctx)
				if err != nil {
					// A valid result is still delivered once; readiness failure
					// retires the worker but must not erase the result.
					return v2InvokeOutcome{Reply: reply, ResultSeen: true, Retirement: err}, nil
				}
				if err := consumeFrame(line); err != nil {
					_ = t.abort()
					return v2InvokeOutcome{Reply: reply, ResultSeen: true, Retirement: err}, nil
				}
				complete, err := decodeStdioJSONV2Frame(line, maxV2WireFrameBytes)
				if err != nil {
					_ = t.abort()
					return v2InvokeOutcome{Reply: reply, ResultSeen: true, Retirement: err}, nil
				}
				if err := validateStdioJSONV2Frame(complete, generation, invocation, ""); err != nil || complete.Kind != "stderr_complete" {
					_ = t.abort()
					return v2InvokeOutcome{Reply: reply, ResultSeen: true, Retirement: fmt.Errorf("invalid stderr_complete")}, nil
				}
				line, err = t.nextFrame(ctx)
				if err != nil {
					_ = t.abort()
					return v2InvokeOutcome{Reply: reply, ResultSeen: true, Retirement: err}, nil
				}
				if err := consumeFrame(line); err != nil {
					_ = t.abort()
					return v2InvokeOutcome{Reply: reply, ResultSeen: true, Retirement: err}, nil
				}
				ready, err := decodeStdioJSONV2Frame(line, maxV2WireFrameBytes)
				if err == nil {
					err = validateInvokeReady(ready, generation, invocation)
				}
				if err != nil {
					_ = t.abort()
					return v2InvokeOutcome{Reply: reply, ResultSeen: true, Retirement: err}, nil
				}
				return v2InvokeOutcome{Reply: reply, ResultSeen: true, Reusable: true}, nil
			}
		}
	}
}

// systemWorkerTransport owns one persistent worker process and all descriptors.
// It is intentionally independent of the evolving SDK session API.
type systemWorkerTransport struct {
	cmd                *exec.Cmd
	stdin              *os.File
	stdout             *os.File
	hostResp           *os.File
	stderr             *os.File
	pgid               int
	scanner            *bufio.Scanner
	frames             chan transportFrame
	done               chan struct{}
	waitDone           chan struct{}
	readDone           chan struct{}
	waitMu             sync.Mutex
	waitErr            error
	requestOnce        sync.Once
	abortDone          chan struct{}
	abortErr           error
	requestErr         error
	abortStage         string
	ownedTerm          bool
	ownedKill          bool
	groupOnce          sync.Once
	groupDone          chan struct{}
	groupErr           error
	stderrDone         chan struct{}
	readPumpErr        error
	stderrPumpErr      error
	closeOnce          sync.Once
	closeErr           error
	rawStderrBytes     atomic.Int64
	beforeAbortFinish  func()
	reapProcessGroupFn func() error
	closePipesFn       func() error
}

type processGroupResidualError struct {
	PGID  int
	Stage string
	Err   error
}

func (e *processGroupResidualError) Error() string {
	return fmt.Sprintf("process group %d %s: %v", e.PGID, e.Stage, e.Err)
}
func (e *processGroupResidualError) Unwrap() error { return e.Err }

func (t *systemWorkerTransport) drainStderr() {
	defer close(t.stderrDone)
	buf := make([]byte, 32*1024)
	for {
		n, err := t.stderr.Read(buf)
		if n > 0 {
			for {
				old := t.rawStderrBytes.Load()
				if old >= HostMaxInvokeStderrBytes {
					break
				}
				next := min(int64(HostMaxInvokeStderrBytes), old+int64(n))
				if t.rawStderrBytes.CompareAndSwap(old, next) {
					break
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				t.waitMu.Lock()
				t.stderrPumpErr = err
				t.waitMu.Unlock()
			}
			return
		}
	}
}

func (t *systemWorkerTransport) nextFrame(ctx context.Context) ([]byte, error) {
	select {
	case f, ok := <-t.frames:
		if !ok {
			return nil, io.ErrUnexpectedEOF
		}
		return f.line, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (t *systemWorkerTransport) readPump() {
	defer close(t.readDone)
	for t.scanner.Scan() {
		select {
		case t.frames <- transportFrame{line: append([]byte(nil), t.scanner.Bytes()...)}:
		case <-t.done:
			return
		}
	}
	err := t.scanner.Err()
	if err != nil && !errors.Is(err, os.ErrClosed) {
		t.waitMu.Lock()
		t.readPumpErr = err
		t.waitMu.Unlock()
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	select {
	case t.frames <- transportFrame{err: err}:
	case <-t.done:
	}
}

func (t *systemWorkerTransport) closePipes() error {
	if t == nil {
		return nil
	}
	t.closeOnce.Do(func() {
		closeFile := func(file *os.File) {
			if file == nil {
				return
			}
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.closeErr = errors.Join(t.closeErr, err)
			}
		}
		closeFile(t.stdin)
		closeFile(t.stdout)
		closeFile(t.hostResp)
		closeFile(t.stderr)
	})
	return t.closeErr
}

func (t *systemWorkerTransport) awaitReady(generation uint64) error {
	if t == nil || t.stdout == nil {
		return fmt.Errorf("worker stdout unavailable")
	}
	if t.scanner == nil {
		return fmt.Errorf("worker decoder unavailable")
	}
	line, err := t.nextFrame(context.Background())
	if err != nil {
		return fmt.Errorf("worker exited before runtime_ready")
	}
	f, err := decodeStdioJSONV2Frame(line)
	if err != nil {
		return fmt.Errorf("decode runtime_ready: %w", err)
	}
	if err := validateStdioJSONV2Frame(f, generation, "runtime", ""); err != nil || f.Kind != "runtime_ready" {
		return fmt.Errorf("invalid runtime_ready")
	}
	return nil
}

func (t *systemWorkerTransport) awaitReadyContext(ctx context.Context, generation uint64) error {
	line, err := t.nextFrame(ctx)
	if err != nil {
		return err
	}
	f, err := decodeStdioJSONV2Frame(line)
	if err != nil {
		return err
	}
	if err := validateStdioJSONV2Frame(f, generation, "runtime", ""); err != nil || f.Kind != "runtime_ready" {
		return fmt.Errorf("invalid runtime_ready")
	}
	return nil
}

func startSystemWorker(ctx context.Context, path, dir string, env []string) (*systemWorkerTransport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.Command(path)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		return nil, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return nil, err
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW
	hostRead, hostWrite, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{hostRead}
	if err := cmd.Start(); err != nil {
		_ = hostRead.Close()
		_ = hostWrite.Close()
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
		return nil, err
	}
	_ = stdinR.Close()
	_ = stdoutW.Close()
	_ = stderrW.Close()
	_ = hostRead.Close()
	t := &systemWorkerTransport{cmd: cmd, stdin: stdinW, stdout: stdoutR, hostResp: hostWrite, stderr: stderrR, pgid: cmd.Process.Pid, scanner: bufio.NewScanner(stdoutR), frames: make(chan transportFrame, 1), done: make(chan struct{}), waitDone: make(chan struct{}), readDone: make(chan struct{}), stderrDone: make(chan struct{}), groupDone: make(chan struct{}), abortDone: make(chan struct{})}
	go func() { err := cmd.Wait(); t.waitMu.Lock(); t.waitErr = err; t.waitMu.Unlock(); close(t.waitDone) }()
	t.scanner.Buffer(make([]byte, 64*1024), maxV2WireFrameBytes)
	go t.readPump()
	go t.drainStderr()
	return t, nil
}

func (t *systemWorkerTransport) abort() error {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return nil
	}
	t.requestAbort()
	return t.waitAbort(context.Background())
}

func (t *systemWorkerTransport) requestAbort() {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return
	}
	t.requestOnce.Do(func() {
		close(t.done)
		t.waitMu.Lock()
		t.abortStage = "term-grace"
		if err := syscall.Kill(-t.pgid, syscall.SIGTERM); err == nil {
			t.ownedTerm = true
		} else if err != syscall.ESRCH {
			t.requestErr = &processGroupResidualError{PGID: t.pgid, Stage: "sigterm", Err: err}
		}
		t.waitMu.Unlock()
		go t.finishAbort()
	})
}

// finishAbort is the sole owner of persistent-process teardown. Callers may
// stop waiting, but this future always continues through group extinction,
// leader/pump joins, and descriptor closure.
func (t *systemWorkerTransport) finishAbort() {
	defer close(t.abortDone)
	if t.beforeAbortFinish != nil {
		t.beforeAbortFinish()
	}
	t.setAbortStage("group-extinction")
	var groupErr error
	if t.reapProcessGroupFn != nil {
		groupErr = t.reapProcessGroupFn()
	} else {
		groupErr = t.reapProcessGroup()
	}
	if groupErr != nil {
		groupErr = &processGroupResidualError{PGID: t.pgid, Stage: "group-extinction", Err: groupErr}
	}
	t.setAbortStage("leader-wait")
	<-t.waitDone

	t.setAbortStage("pipe-close")
	pipeErr := t.closePipes()
	if t.closePipesFn != nil {
		pipeErr = errors.Join(pipeErr, t.closePipesFn())
	}
	if pipeErr != nil {
		pipeErr = &processGroupResidualError{PGID: t.pgid, Stage: "pipe-close", Err: pipeErr}
	}
	t.setAbortStage("stdout-join")
	<-t.readDone
	t.setAbortStage("stderr-join")
	<-t.stderrDone

	t.waitMu.Lock()
	waitErr := t.waitErr
	if signal, ok := transportExitSignal(waitErr); ok && groupErr == nil && !processGroupExists(t.pgid) &&
		((signal == syscall.SIGTERM && t.ownedTerm) || (signal == syscall.SIGKILL && t.ownedKill)) {
		waitErr = nil
	}
	if waitErr != nil {
		waitErr = &processGroupResidualError{PGID: t.pgid, Stage: "leader-wait", Err: waitErr}
	}
	readErr := t.readPumpErr
	if readErr != nil {
		readErr = &processGroupResidualError{PGID: t.pgid, Stage: "stdout-join", Err: readErr}
	}
	stderrErr := t.stderrPumpErr
	if stderrErr != nil {
		stderrErr = &processGroupResidualError{PGID: t.pgid, Stage: "stderr-join", Err: stderrErr}
	}
	t.abortErr = errors.Join(t.requestErr, groupErr, waitErr, pipeErr, readErr, stderrErr)
	t.abortStage = "complete"
	t.waitMu.Unlock()
}

func transportExitSignal(err error) (syscall.Signal, bool) {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return 0, false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return 0, false
	}
	return status.Signal(), true
}

func (t *systemWorkerTransport) setAbortStage(stage string) {
	t.waitMu.Lock()
	t.abortStage = stage
	t.waitMu.Unlock()
}

func (t *systemWorkerTransport) waitAbort(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-t.abortDone:
		t.waitMu.Lock()
		err := t.abortErr
		t.waitMu.Unlock()
		return err
	case <-ctx.Done():
		t.waitMu.Lock()
		stage := t.abortStage
		t.waitMu.Unlock()
		if stage == "" {
			stage = "abort-pending"
		}
		return &processGroupResidualError{PGID: t.pgid, Stage: stage, Err: ctx.Err()}
	}
}

func (t *systemWorkerTransport) reapProcessGroup() error {
	t.groupOnce.Do(func() {
		t.groupErr = terminateProcessGroupWithSignalRecord(t.pgid, 100*time.Millisecond, func(signal syscall.Signal) {
			if signal != syscall.SIGKILL {
				return
			}
			t.waitMu.Lock()
			t.ownedKill = true
			t.waitMu.Unlock()
		})
		close(t.groupDone)
	})
	<-t.groupDone
	return t.groupErr
}

func (t *systemWorkerTransport) wait() error {
	if t == nil || t.cmd == nil {
		return nil
	}
	<-t.waitDone
	if processGroupExists(t.pgid) {
		_ = t.reapProcessGroup()
	}
	<-t.readDone
	<-t.stderrDone
	t.closePipes()
	t.waitMu.Lock()
	defer t.waitMu.Unlock()
	return t.waitErr
}
