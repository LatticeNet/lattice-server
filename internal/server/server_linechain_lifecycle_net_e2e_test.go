//go:build linechain_lifecycle_e2e

package server

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type lifecycleObserver struct {
	listener net.Listener
	target   string
	mu       sync.Mutex
	count    int
}

func lifecycleFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func lifecycleEchoOrigin(t *testing.T) *net.TCPAddr {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr)
}

func newLifecycleObserver(t *testing.T, target string) *lifecycleObserver {
	return newLifecycleObserverAtPort(t, target, 0)
}

func newLifecycleObserverAtPort(t *testing.T, target string, port int) *lifecycleObserver {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	o := &lifecycleObserver{listener: l, target: target}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			incoming, err := l.Accept()
			if err != nil {
				return
			}
			o.mu.Lock()
			o.count++
			o.mu.Unlock()
			go func() {
				defer incoming.Close()
				outgoing, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer outgoing.Close()
				go io.Copy(outgoing, incoming)
				_, _ = io.Copy(incoming, outgoing)
			}()
		}
	}()
	return o
}

func (o *lifecycleObserver) port() int { return o.listener.Addr().(*net.TCPAddr).Port }
func (o *lifecycleObserver) accepted() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.count
}
func (o *lifecycleObserver) reset() {
	o.mu.Lock()
	o.count = 0
	o.mu.Unlock()
}

func lifecycleRealityKeypair(t *testing.T, bin string) (string, string) {
	t.Helper()
	out, err := exec.Command(bin, "generate", "reality-keypair").CombinedOutput()
	if err != nil {
		t.Fatalf("generate reality keypair: %v: %s", err, out)
	}
	var privateKey, publicKey string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "PrivateKey: ") {
			privateKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey: "))
		}
		if strings.HasPrefix(line, "PublicKey: ") {
			publicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey: "))
		}
	}
	if privateKey == "" || publicKey == "" {
		t.Fatalf("incomplete reality keypair: %s", out)
	}
	return privateKey, publicKey
}

func lifecycleWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lifecycleStartProcess(t *testing.T, bin, root, name, configDir string, port int) {
	t.Helper()
	cmd := exec.Command(bin, "run", "-C", configDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	logPath := filepath.Join(root, name+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name+".pid"), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); _ = logFile.Close() }()
	t.Cleanup(func() {
		pgid := -cmd.Process.Pid
		lifecycleStopPGID(t, pgid, done, name)
		// A managed restart may replace the process recorded at startup; join
		// the currently owned pidfile process group as well.
		if raw, err := os.ReadFile(filepath.Join(root, name+".pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 && pid != cmd.Process.Pid {
				current := -pid
				lifecycleStopPGID(t, current, nil, name+"-restarted")
			}
			_ = os.Remove(filepath.Join(root, name+".pid"))
		}
	})
	if err := lifecycleWaitPort(port, 5*time.Second); err != nil {
		raw, _ := os.ReadFile(logPath)
		t.Fatalf("start %s: %v: %s", name, err, raw)
	}
}

func lifecycleStopPGID(t *testing.T, pgid int, done <-chan error, name string) {
	t.Helper()
	_ = syscall.Kill(pgid, syscall.SIGTERM)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pgid, 0) != nil {
			if done != nil {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Errorf("%s wait did not complete", name)
				}
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(pgid, syscall.SIGKILL)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pgid, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("%s process group did not exit", name)
}

func lifecycleWaitPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("port %d did not become ready", port)
}

func lifecycleSOCKSEcho(t *testing.T, socksPort int, target *net.TCPAddr) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil || response[1] != 0 {
		t.Fatalf("SOCKS greeting=%v err=%v", response, err)
	}
	ip := target.IP.To4()
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(request[len(request)-2:], uint16(target.Port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil || header[1] != 0 {
		t.Fatalf("SOCKS connect=%v err=%v", header, err)
	}
	switch header[3] {
	case 1:
		_, err = io.ReadFull(reader, make([]byte, 6))
	case 4:
		_, err = io.ReadFull(reader, make([]byte, 18))
	case 3:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			err = readErr
		} else {
			_, err = io.ReadFull(reader, make([]byte, int(length)+2))
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("server-issued-linechain")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != string(payload) {
		t.Fatalf("echo=%q err=%v", echo, err)
	}
}

func lifecycleKillProcessGroup(t *testing.T, cmd *exec.Cmd, done <-chan error) {
	t.Helper()
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("helper process group did not exit")
	}
}

func lifecycleKillPIDFile(root, name string) {
	raw, err := os.ReadFile(filepath.Join(root, name+".pid"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err == nil && pid > 1 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
