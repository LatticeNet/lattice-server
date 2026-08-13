package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// systemWorkerTransport owns one persistent worker process and all descriptors.
// It is intentionally independent of the evolving SDK session API.
type systemWorkerTransport struct {
	cmd      *exec.Cmd
	stdin    *os.File
	stdout   *os.File
	hostResp *os.File
	stderr   *os.File
	pgid     int
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
	s := bufio.NewScanner(t.stdout)
	s.Buffer(make([]byte, 0, 4096), 64*1024)
	if !s.Scan() {
		return fmt.Errorf("worker exited before runtime_ready")
	}
	var f stdioJSONV2Frame
	if err := json.Unmarshal(s.Bytes(), &f); err != nil {
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
	cmd := exec.CommandContext(ctx, path)
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
	return &systemWorkerTransport{cmd: cmd, stdin: in.(*os.File), stdout: out.(*os.File), hostResp: hostWrite, stderr: errout.(*os.File), pgid: cmd.Process.Pid}, nil
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
