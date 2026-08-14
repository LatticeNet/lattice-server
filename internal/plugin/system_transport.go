package plugin

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
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
}

func (t *systemWorkerTransport) invokeV2(ctx context.Context, generation uint64, invocation string, req InvokeRequest, host func(systemHostCall) systemHostResponse, budgets ...ResolvedInvokeBudget) (outcome v2InvokeOutcome, callErr error) {
	if t == nil || t.stdin == nil || t.scanner == nil {
		return v2InvokeOutcome{}, fmt.Errorf("worker transport unavailable")
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
	go func() { write <- json.NewEncoder(t.stdin).Encode(frame) }()
	select {
	case err := <-write:
		if err != nil {
			return v2InvokeOutcome{}, err
		}
	case <-ctx.Done():
		_ = t.abort()
		return v2InvokeOutcome{}, ctx.Err()
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
			return v2InvokeOutcome{}, err
		}
		line = fr
		f, err := decodeStdioJSONV2Frame(line, maxV2WireFrameBytes)
		if err != nil {
			return v2InvokeOutcome{}, err
		}
		if err := validateStdioJSONV2Frame(f, generation, invocation, ""); err != nil {
			return v2InvokeOutcome{}, err
		}
		if f.Kind != "stderr_chunk" {
			if err := consumeFrame(line); err != nil {
				return v2InvokeOutcome{}, err
			}
		}
		if f.Kind == "host_call" {
			if host == nil || f.HostCallID == "" {
				return v2InvokeOutcome{}, fmt.Errorf("invalid host call")
			}
			if _, duplicate := seenHostCalls[f.HostCallID]; duplicate {
				return v2InvokeOutcome{}, fmt.Errorf("duplicate host_call_id %q", f.HostCallID)
			}
			if len(seenHostCalls) >= hostCallLimit {
				return v2InvokeOutcome{}, fmt.Errorf("plugin exceeded host-call limit %d", hostCallLimit)
			}
			seenHostCalls[f.HostCallID] = struct{}{}
			call, err := decodeStrictSystemHostCall(f.HostCall, f.HostCallID, HostMaxInvokeStdoutBytes)
			if err != nil {
				return v2InvokeOutcome{}, err
			}
			resp := host(call)
			out := stdioJSONV2Frame{Protocol: 2, Kind: "host_response", Generation: generation, InvocationID: invocation, HostCallID: f.HostCallID}
			out.HostResponse, _ = json.Marshal(resp)
			writeResp := make(chan error, 1)
			go func() { writeResp <- json.NewEncoder(t.hostResp).Encode(out) }()
			select {
			case err := <-writeResp:
				if err != nil {
					return v2InvokeOutcome{}, err
				}
			case <-ctx.Done():
				_ = t.abort()
				return v2InvokeOutcome{}, ctx.Err()
			}
			continue
		}
		if f.Kind == "stderr_chunk" {
			diagnosticChunks++
			diagnosticWireConsumed += len(line) + 1
			if diagnosticChunks > maxV2DiagnosticChunks || diagnosticWireConsumed > maxV2DiagnosticWireBytes {
				return v2InvokeOutcome{}, fmt.Errorf("plugin exceeded diagnostic frame limit")
			}
			if len(f.Data) > base64.StdEncoding.EncodedLen(HostMaxInvokeStderrBytes) || base64.StdEncoding.DecodedLen(len(f.Data)) > HostMaxInvokeStderrBytes {
				return v2InvokeOutcome{}, fmt.Errorf("stderr_chunk exceeds host maximum")
			}
			chunk, err := base64.StdEncoding.DecodeString(f.Data)
			if err != nil {
				return v2InvokeOutcome{}, fmt.Errorf("invalid stderr_chunk data")
			}
			if len(chunk) > HostMaxInvokeStderrBytes-diagnosticDecodedTotal {
				return v2InvokeOutcome{}, fmt.Errorf("plugin exceeded diagnostic decoded limit %d", HostMaxInvokeStderrBytes)
			}
			diagnosticDecodedTotal += len(chunk)
			_, _ = diagnostics.Write(chunk)
			continue
		}
		if f.Kind == "invoke_ready" {
			return v2InvokeOutcome{}, fmt.Errorf("invoke_ready before result")
		}
		if f.Kind != "invoke_result" {
			return v2InvokeOutcome{}, fmt.Errorf("unexpected v2 frame %q", f.Kind)
		}
		reply, err := decodeSystemRunnerReply(f.Response, HostMaxInvokeStdoutBytes)
		if err != nil {
			return v2InvokeOutcome{}, err
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
	cmd            *exec.Cmd
	stdin          *os.File
	stdout         *os.File
	hostResp       *os.File
	stderr         *os.File
	pgid           int
	scanner        *bufio.Scanner
	frames         chan transportFrame
	done           chan struct{}
	waitDone       chan struct{}
	readDone       chan struct{}
	waitMu         sync.Mutex
	waitErr        error
	abortOnce      sync.Once
	abortErr       error
	stderrDone     chan struct{}
	rawStderrBytes atomic.Int64
}

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
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	select {
	case t.frames <- transportFrame{err: err}:
	case <-t.done:
	}
}

func (t *systemWorkerTransport) closePipes() {
	if t == nil {
		return
	}
	if t.stdin != nil {
		_ = t.stdin.Close()
	}
	if t.stdout != nil {
		_ = t.stdout.Close()
	}
	if t.hostResp != nil {
		_ = t.hostResp.Close()
	}
	if t.stderr != nil {
		_ = t.stderr.Close()
	}
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
		_ = t.abort()
		return err
	}
	f, err := decodeStdioJSONV2Frame(line)
	if err != nil {
		_ = t.abort()
		return err
	}
	if err := validateStdioJSONV2Frame(f, generation, "runtime", ""); err != nil || f.Kind != "runtime_ready" {
		_ = t.abort()
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
	t := &systemWorkerTransport{cmd: cmd, stdin: stdinW, stdout: stdoutR, hostResp: hostWrite, stderr: stderrR, pgid: cmd.Process.Pid, scanner: bufio.NewScanner(stdoutR), frames: make(chan transportFrame, 1), done: make(chan struct{}), waitDone: make(chan struct{}), readDone: make(chan struct{}), stderrDone: make(chan struct{})}
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
	t.abortOnce.Do(func() {
		close(t.done)
		_ = syscall.Kill(-t.pgid, syscall.SIGTERM)
		done := t.waitDone
		select {
		case <-done:
			t.waitMu.Lock()
			t.abortErr = t.waitErr
			t.waitMu.Unlock()
		case <-time.After(100 * time.Millisecond):
			_ = syscall.Kill(-t.pgid, syscall.SIGKILL)
			<-done
			t.waitMu.Lock()
			t.abortErr = t.waitErr
			t.waitMu.Unlock()
		}
		t.closePipes()
		<-t.readDone
		<-t.stderrDone
	})
	return t.abortErr
}

func (t *systemWorkerTransport) wait() error {
	if t == nil || t.cmd == nil {
		return nil
	}
	<-t.waitDone
	<-t.readDone
	<-t.stderrDone
	t.closePipes()
	t.waitMu.Lock()
	defer t.waitMu.Unlock()
	return t.waitErr
}
