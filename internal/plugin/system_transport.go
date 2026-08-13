package plugin

import (
	"context"
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
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &systemWorkerTransport{cmd: cmd, stdin: in.(*os.File), stdout: out.(*os.File), stderr: errout.(*os.File), pgid: cmd.Process.Pid}, nil
}

func (t *systemWorkerTransport) abort() error {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return nil
	}
	_ = syscall.Kill(-t.pgid, syscall.SIGTERM)
	_ = syscall.Kill(-t.pgid, syscall.SIGKILL)
	return t.cmd.Wait()
}

func (t *systemWorkerTransport) wait() error {
	if t == nil || t.cmd == nil {
		return nil
	}
	return t.cmd.Wait()
}
