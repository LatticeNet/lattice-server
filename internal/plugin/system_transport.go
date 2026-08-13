package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

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

func (t *systemWorkerTransport) invokeV2(ctx context.Context, generation uint64, invocation string, req InvokeRequest, host func(systemHostCall) systemHostResponse) (systemRunnerReply, error) {
	if t == nil || t.stdin == nil || t.scanner == nil {
		return systemRunnerReply{}, fmt.Errorf("worker transport unavailable")
	}
	frame := stdioJSONV2Frame{Protocol: 2, Kind: "invoke", Generation: generation, InvocationID: invocation}
	frame.Request, _ = json.Marshal(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{req.Action, req.Payload})
	write := make(chan error, 1)
	go func() { write <- json.NewEncoder(t.stdin).Encode(frame) }()
	select {
	case err := <-write:
		if err != nil {
			return systemRunnerReply{}, err
		}
	case <-ctx.Done():
		_ = t.abort()
		return systemRunnerReply{}, ctx.Err()
	}
	for {
		var line []byte
		fr, err := t.nextFrame(ctx)
		if err != nil {
			_ = t.abort()
			return systemRunnerReply{}, err
		}
		line = fr
		var f stdioJSONV2Frame
		if err := decodeStrictV2(line, &f); err != nil {
			return systemRunnerReply{}, err
		}
		if err := validateStdioJSONV2Frame(f, generation, invocation, ""); err != nil {
			return systemRunnerReply{}, err
		}
		if f.Kind == "host_call" {
			if host == nil || f.HostCallID == "" {
				return systemRunnerReply{}, fmt.Errorf("invalid host call")
			}
			var call systemHostCall
			if err := decodeStrictV2(f.HostCall, &call); err != nil {
				return systemRunnerReply{}, err
			}
			if call.ID != "" && call.ID != f.HostCallID {
				return systemRunnerReply{}, fmt.Errorf("host call id mismatch")
			}
			resp := host(call)
			out := stdioJSONV2Frame{Protocol: 2, Kind: "host_response", Generation: generation, InvocationID: invocation, HostCallID: f.HostCallID}
			out.HostResponse, _ = json.Marshal(resp)
			writeResp := make(chan error, 1)
			go func() { writeResp <- json.NewEncoder(t.hostResp).Encode(out) }()
			select {
			case err := <-writeResp:
				if err != nil {
					return systemRunnerReply{}, err
				}
			case <-ctx.Done():
				_ = t.abort()
				return systemRunnerReply{}, ctx.Err()
			}
			continue
		}
		if f.Kind == "invoke_ready" {
			return systemRunnerReply{}, fmt.Errorf("invoke_ready before result")
		}
		if f.Kind != "invoke_result" {
			return systemRunnerReply{}, fmt.Errorf("unexpected v2 frame %q", f.Kind)
		}
		var reply systemRunnerReply
		if err := json.Unmarshal(f.Response, &reply); err != nil {
			return systemRunnerReply{}, err
		}
		if f.Kind == "invoke_result" {
			for {
				var err error
				line, err = t.nextFrame(ctx)
				if err != nil {
					// A valid result is still delivered once; readiness failure
					// retires the worker but must not erase the result.
					return reply, err
				}
				var ready stdioJSONV2Frame
				if err := decodeStrictV2(line, &ready); err != nil {
					return systemRunnerReply{}, err
				}
				if err := validateInvokeReady(ready, generation, invocation); err == nil {
					return reply, nil
				}
				_ = t.abort()
				return reply, fmt.Errorf("invalid invoke_ready")
			}
		}
	}
}

// systemWorkerTransport owns one persistent worker process and all descriptors.
// It is intentionally independent of the evolving SDK session API.
type systemWorkerTransport struct {
	cmd       *exec.Cmd
	stdin     *os.File
	stdout    *os.File
	hostResp  *os.File
	stderr    *os.File
	pgid      int
	scanner   *bufio.Scanner
	frames    chan transportFrame
	done      chan struct{}
	waitDone  chan error
	abortOnce sync.Once
	abortErr  error
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
	var f stdioJSONV2Frame
	if err := decodeStrictV2(line, &f); err != nil {
		return fmt.Errorf("decode runtime_ready: %w", err)
	}
	if f.Kind != "runtime_ready" {
		return fmt.Errorf("expected runtime_ready, got %q", f.Kind)
	}
	if f.Generation != generation || f.Protocol != 2 {
		return fmt.Errorf("runtime_ready correlation mismatch")
	}
	return nil
}

func (t *systemWorkerTransport) awaitReadyContext(ctx context.Context, generation uint64) error {
	result := make(chan error, 1)
	go func() { result <- t.awaitReady(generation) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		_ = t.abort()
		return ctx.Err()
	}
}

func startSystemWorker(ctx context.Context, path, dir string, env []string) (*systemWorkerTransport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.Command(path)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	errout, err := cmd.StderrPipe()
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	hostRead, hostWrite, err := os.Pipe()
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{hostRead}
	if err := cmd.Start(); err != nil {
		_ = hostRead.Close()
		_ = hostWrite.Close()
		return nil, err
	}
	_ = hostRead.Close()
	t := &systemWorkerTransport{cmd: cmd, stdin: in.(*os.File), stdout: out.(*os.File), hostResp: hostWrite, stderr: errout.(*os.File), pgid: cmd.Process.Pid, scanner: bufio.NewScanner(out), frames: make(chan transportFrame, 1), done: make(chan struct{}), waitDone: make(chan error, 1)}
	go func() { t.waitDone <- cmd.Wait() }()
	t.scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	go t.readPump()
	return t, nil
}

func (t *systemWorkerTransport) abort() error {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return nil
	}
	t.abortOnce.Do(func() {
		close(t.done)
		_ = syscall.Kill(-t.pgid, syscall.SIGTERM)
		done := make(chan error, 1)
		done = t.waitDone
		select {
		case t.abortErr = <-done:
		case <-time.After(100 * time.Millisecond):
			_ = syscall.Kill(-t.pgid, syscall.SIGKILL)
			t.abortErr = <-done
		}
		t.closePipes()
	})
	return t.abortErr
}

func (t *systemWorkerTransport) wait() error {
	if t == nil || t.cmd == nil {
		return nil
	}
	return <-t.waitDone
}
