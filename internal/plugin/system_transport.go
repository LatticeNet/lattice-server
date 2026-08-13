package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

func (t *systemWorkerTransport) invokeV2(generation uint64, invocation string, req InvokeRequest) (systemRunnerReply, error) {
	if t == nil || t.stdin == nil || t.scanner == nil {
		return systemRunnerReply{}, fmt.Errorf("worker transport unavailable")
	}
	frame := stdioJSONV2Frame{Protocol: 2, Kind: "invoke", Generation: generation, InvocationID: invocation}
	frame.Request, _ = json.Marshal(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{req.Action, req.Payload})
	if err := json.NewEncoder(t.stdin).Encode(frame); err != nil {
		return systemRunnerReply{}, err
	}
	for t.scanner.Scan() {
		var f stdioJSONV2Frame
		if err := json.Unmarshal(t.scanner.Bytes(), &f); err != nil {
			return systemRunnerReply{}, err
		}
		if err := validateStdioJSONV2Frame(f, generation, invocation, ""); err != nil {
			return systemRunnerReply{}, err
		}
		if f.Kind == "host_call" {
			continue
		}
		if f.Kind != "invoke_result" {
			return systemRunnerReply{}, fmt.Errorf("unexpected v2 frame %q", f.Kind)
		}
		var reply systemRunnerReply
		if err := json.Unmarshal(f.Response, &reply); err != nil {
			return systemRunnerReply{}, err
		}
		if !t.scanner.Scan() {
			return systemRunnerReply{}, io.ErrUnexpectedEOF
		}
		var ready stdioJSONV2Frame
		if err := json.Unmarshal(t.scanner.Bytes(), &ready); err != nil || ready.Kind != "invoke_ready" {
			return systemRunnerReply{}, fmt.Errorf("missing invoke_ready")
		}
		return reply, nil
	}
	return systemRunnerReply{}, io.ErrUnexpectedEOF
}

// systemWorkerTransport owns one persistent worker process and all descriptors.
// It is intentionally independent of the evolving SDK session API.
type systemWorkerTransport struct {
	cmd      *exec.Cmd
	stdin    *os.File
	stdout   *os.File
	hostResp *os.File
	stderr   *os.File
	pgid     int
	scanner  *bufio.Scanner
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
	if err := json.Unmarshal(t.scanner.Bytes(), &f); err != nil {
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

func startSystemWorker(ctx context.Context, path, dir string, env []string) (*systemWorkerTransport, error) {
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
	_ = syscall.Kill(-t.pgid, syscall.SIGTERM)
	_ = syscall.Kill(-t.pgid, syscall.SIGKILL)
	err := t.cmd.Wait()
	t.closePipes()
	return err
}

func (t *systemWorkerTransport) wait() error {
	if t == nil || t.cmd == nil {
		return nil
	}
	return t.cmd.Wait()
}
