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
)

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
		lines := make(chan []byte, 1)
		errs := make(chan error, 1)
		go func() {
			if t.scanner.Scan() {
				lines <- append([]byte(nil), t.scanner.Bytes()...)
				return
			}
			errs <- io.ErrUnexpectedEOF
		}()
		var line []byte
		select {
		case line = <-lines:
		case err := <-errs:
			return systemRunnerReply{}, err
		case <-ctx.Done():
			_ = t.abort()
			return systemRunnerReply{}, ctx.Err()
		}
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
			if err := json.NewEncoder(t.hostResp).Encode(out); err != nil {
				return systemRunnerReply{}, err
			}
			continue
		}
		if f.Kind != "invoke_result" {
			return systemRunnerReply{}, fmt.Errorf("unexpected v2 frame %q", f.Kind)
		}
		var reply systemRunnerReply
		if err := json.Unmarshal(f.Response, &reply); err != nil {
			return systemRunnerReply{}, err
		}
		if f.Kind == "invoke_ready" {
			return systemRunnerReply{}, fmt.Errorf("invoke_ready before result")
		}
		if f.Kind == "invoke_result" {
			for {
				lines := make(chan []byte, 1)
				errs := make(chan error, 1)
				go func() {
					if t.scanner.Scan() {
						lines <- append([]byte(nil), t.scanner.Bytes()...)
					} else {
						errs <- io.ErrUnexpectedEOF
					}
				}()
				select {
				case line = <-lines:
				case err := <-errs:
					return systemRunnerReply{}, err
				case <-ctx.Done():
					_ = t.abort()
					return systemRunnerReply{}, ctx.Err()
				}
				var ready stdioJSONV2Frame
				if err := decodeStrictV2(line, &ready); err != nil {
					return systemRunnerReply{}, err
				}
				if ready.Kind == "invoke_ready" && ready.Generation == generation && ready.InvocationID == invocation {
					return reply, nil
				}
				return systemRunnerReply{}, fmt.Errorf("missing invoke_ready")
			}
		}
	}
	return systemRunnerReply{}, io.ErrUnexpectedEOF
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
	abortOnce sync.Once
	abortErr  error
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
	if !t.scanner.Scan() {
		return fmt.Errorf("worker exited before runtime_ready")
	}
	var f stdioJSONV2Frame
	if err := decodeStrictV2(t.scanner.Bytes(), &f); err != nil {
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
	t := &systemWorkerTransport{cmd: cmd, stdin: in.(*os.File), stdout: out.(*os.File), hostResp: hostWrite, stderr: errout.(*os.File), pgid: cmd.Process.Pid}
	t.scanner = bufio.NewScanner(t.stdout)
	t.scanner.Buffer(make([]byte, 0, 4096), 64*1024)
	return t, nil
}

func (t *systemWorkerTransport) abort() error {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return nil
	}
	t.abortOnce.Do(func() {
		_ = syscall.Kill(-t.pgid, syscall.SIGTERM)
		_ = syscall.Kill(-t.pgid, syscall.SIGKILL)
		t.abortErr = t.cmd.Wait()
		t.closePipes()
	})
	return t.abortErr
}

func (t *systemWorkerTransport) wait() error {
	if t == nil || t.cmd == nil {
		return nil
	}
	return t.cmd.Wait()
}
