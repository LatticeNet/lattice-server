//go:build linux

package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Design 30 verification on a real kernel. These tests start real plugin
// children through both spawn paths (a v1 invocation and a pooled v2 worker)
// and read what the kernel says about them. They need a process that can
// drop its children: root, or the server's own file capabilities
// (cap_setuid, cap_setgid, cap_kill in the effective set), which is how
// production runs. Without either they skip, unless
// LATTICE_TEST_REQUIRE_UID_DROP=1 asks them to fail instead, so a CI job
// meant to run them cannot pass by skipping.
//
// The same test binary is the plugin: a child started with
// LATTICE_TEST_ISOLATION_PROBE=1 runs runIsolationProbe from init and
// reports its identity, capabilities and what it could reach.

const (
	capKill   = 5
	capSetgid = 6
	capSetuid = 7
)

func init() {
	if os.Getenv("LATTICE_TEST_ISOLATION_PROBE") == "1" {
		runIsolationProbe()
		os.Exit(0)
	}
}

type isolationProbeRequest struct {
	Sockets      []string `json:"sockets"`
	Secret       string   `json:"secret"`
	SetuidTo     []int    `json:"setuid_to"`
	ServerPID    int      `json:"server_pid"`
	SiblingPID   int      `json:"sibling_pid"`
	TryPtrace    bool     `json:"try_ptrace"`
	HangAfterLog bool     `json:"hang_after_log"`
}

type isolationReport struct {
	PID           int               `json:"pid"`
	Status        map[string]string `json:"status"`
	Cwd           string            `json:"cwd"`
	ListCwd       string            `json:"list_cwd"`
	WriteCwd      string            `json:"write_cwd"`
	Sockets       map[string]string `json:"sockets"`
	Secret        string            `json:"secret"`
	KillServer    string            `json:"kill_server"`
	PtraceServer  string            `json:"ptrace_server"`
	KillSibling   string            `json:"kill_sibling"`
	PtraceSibling string            `json:"ptrace_sibling"`
	Setuid        map[string]string `json:"setuid"`
	HostCall      string            `json:"host_call"`
}

func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return err.Error()
}

func readProcStatus(pid string) map[string]string {
	raw, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd", "NoNewPrivs":
			out[key] = strings.Join(strings.Fields(value), " ")
		}
	}
	return out
}

// tryPtrace attaches to pid and, if that unexpectedly works, detaches again
// so the probe never leaves a process stopped.
func tryPtrace(pid int) string {
	done := make(chan string, 1)
	go func() {
		// The thread stays locked and is discarded when the goroutine
		// ends, so no ptrace state outlives this call.
		runtime.LockOSThread()
		err := syscall.PtraceAttach(pid)
		if err == nil {
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &ws, syscall.WALL, nil)
			_ = syscall.PtraceDetach(pid)
		}
		done <- outcome(err)
	}()
	return <-done
}

// trySetuid calls setuid on a throwaway thread, so a success (which the
// tests treat as a failure of the boundary) cannot leak into the rest of the
// probe.
func trySetuid(uid int) string {
	done := make(chan string, 1)
	go func() {
		runtime.LockOSThread()
		_, _, errno := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(uid), 0, 0)
		if errno != 0 {
			done <- errno.Error()
			return
		}
		done <- "ok"
	}()
	return <-done
}

func probeReport(req isolationProbeRequest, hostCall func(message string) error) isolationReport {
	rep := isolationReport{PID: os.Getpid(), Status: readProcStatus("self"), Sockets: map[string]string{}, Setuid: map[string]string{}}
	rep.HostCall = outcome(hostCall(fmt.Sprintf("isolation probe pid=%d", os.Getpid())))
	if req.HangAfterLog {
		// Sleep rather than block forever: a probe with nothing left to run
		// would be killed by the runtime's deadlock check, not by the server.
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Hour)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		rep.Cwd = cwd
	} else {
		rep.Cwd = outcome(err)
	}
	_, err := os.ReadDir(".")
	rep.ListCwd = outcome(err)
	err = os.WriteFile("planted", []byte("x"), 0o755)
	rep.WriteCwd = outcome(err)
	if err == nil {
		_ = os.Remove("planted")
	}
	for _, path := range req.Sockets {
		conn, err := net.DialTimeout("unix", path, 2*time.Second)
		if err == nil {
			_ = conn.Close()
		}
		rep.Sockets[path] = outcome(err)
	}
	if req.Secret != "" {
		_, err := os.ReadFile(req.Secret)
		rep.Secret = outcome(err)
	}
	if req.ServerPID > 0 {
		rep.KillServer = outcome(syscall.Kill(req.ServerPID, 0))
		if req.TryPtrace {
			rep.PtraceServer = tryPtrace(req.ServerPID)
		}
	}
	if req.SiblingPID > 0 {
		rep.KillSibling = outcome(syscall.Kill(req.SiblingPID, 0))
		if req.TryPtrace {
			rep.PtraceSibling = tryPtrace(req.SiblingPID)
		}
	}
	// Last: a setuid that works changes the thread it ran on.
	for _, uid := range req.SetuidTo {
		rep.Setuid[strconv.Itoa(uid)] = trySetuid(uid)
	}
	return rep
}

func runIsolationProbe() {
	hostResponses := bufio.NewReader(os.NewFile(3, "host-response"))
	if os.Getenv("LATTICE_TEST_PROBE_IGNORE_TERM") == "1" {
		signal.Ignore(syscall.SIGTERM)
	}
	enc := json.NewEncoder(os.Stdout)
	if os.Getenv("LATTICE_RUNTIME_PROTOCOL") != RuntimeProtocolStdioJSONV2 {
		// stdio-json v1: one request line, host calls on stdout answered on
		// fd 3, one reply line.
		line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
		if err != nil && len(line) == 0 {
			os.Exit(3)
		}
		var in struct {
			Payload isolationProbeRequest `json:"payload"`
		}
		_ = json.Unmarshal(line, &in)
		rep := probeReport(in.Payload, func(message string) error {
			call := map[string]any{"host_call": map[string]any{"id": "h1", "method": "log.write", "params": map[string]any{"level": "info", "message": message}}}
			if err := enc.Encode(call); err != nil {
				return err
			}
			raw, err := hostResponses.ReadBytes('\n')
			if err != nil {
				return err
			}
			var frame struct {
				HostResponse systemHostResponse `json:"host_response"`
			}
			if err := json.Unmarshal(raw, &frame); err != nil {
				return err
			}
			if !frame.HostResponse.OK {
				return errors.New(frame.HostResponse.Error)
			}
			return nil
		})
		_ = enc.Encode(map[string]any{"ok": true, "result": rep})
		return
	}
	generation, err := strconv.ParseUint(os.Getenv("LATTICE_RUNTIME_GENERATION"), 10, 64)
	if err != nil || generation == 0 {
		os.Exit(6)
	}
	_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "runtime_ready", Generation: generation, InvocationID: "runtime", Features: []string{"stderr_frames_v1"}})
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 64*1024), 4<<20)
	for s.Scan() {
		var f stdioJSONV2Frame
		if json.Unmarshal(s.Bytes(), &f) != nil {
			os.Exit(3)
		}
		var in struct {
			Payload isolationProbeRequest `json:"payload"`
		}
		_ = json.Unmarshal(f.Request, &in)
		rep := probeReport(in.Payload, func(message string) error {
			call, _ := json.Marshal(map[string]any{"id": "h1", "method": "log.write", "params": map[string]any{"level": "info", "message": message}})
			if err := enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "host_call", Generation: f.Generation, InvocationID: f.InvocationID, HostCallID: "h1", HostCall: call}); err != nil {
				return err
			}
			raw, err := hostResponses.ReadBytes('\n')
			if err != nil {
				return err
			}
			var frame stdioJSONV2Frame
			if err := json.Unmarshal(raw, &frame); err != nil {
				return err
			}
			var resp systemHostResponse
			if err := json.Unmarshal(frame.HostResponse, &resp); err != nil {
				return err
			}
			if !resp.OK {
				return errors.New(resp.Error)
			}
			return nil
		})
		result, _ := json.Marshal(map[string]any{"ok": true, "result": rep})
		_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: f.Generation, InvocationID: f.InvocationID, Response: result})
		_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_complete", Generation: f.Generation, InvocationID: f.InvocationID})
		_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "invoke_ready", Generation: f.Generation, InvocationID: f.InvocationID})
	}
}

// requireUIDDrop skips (or, under LATTICE_TEST_REQUIRE_UID_DROP=1, fails)
// unless this process can set a child's uid, gid and groups and signal it
// afterwards.
//
// LATTICE_TEST_SKIP_CAP_GATE=1 runs the tests whatever the capabilities, for
// the negative controls: with a capability missing, or granted as ambient
// instead of as file capabilities, the tests must fail.
func requireUIDDrop(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 || os.Getenv("LATTICE_TEST_SKIP_CAP_GATE") == "1" {
		return
	}
	eff, err := strconv.ParseUint(readProcStatus("self")["CapEff"], 16, 64)
	want := uint64(1)<<capSetuid | 1<<capSetgid | 1<<capKill
	if err == nil && eff&want == want {
		return
	}
	msg := "needs root or the server's file capabilities (cap_setuid, cap_setgid, cap_kill); run it in the Linux container"
	if os.Getenv("LATTICE_TEST_REQUIRE_UID_DROP") == "1" {
		t.Fatal(msg)
	}
	t.Skip(msg)
}

// isolationFixture is a runtime root a foreign uid can reach (the analogue of
// /var/lib/lattice at 0755), with stand-ins for the probe socket and
// master.key beside it.
type isolationFixture struct {
	runtimeDir string
	bundle     string
	sockets    []string
	secret     string
	serverUID  int
	groupLine  string
}

func newIsolationFixture(t *testing.T) isolationFixture {
	t.Helper()
	base := t.TempDir()
	// t.TempDir makes its parent and the directory 0700; open both to 0755
	// as /var/lib/lattice is, so only the modes under test decide access.
	for _, dir := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := isolationFixture{runtimeDir: filepath.Join(base, "plugin-runtime"), serverUID: os.Geteuid(), groupLine: readProcStatus("self")["Groups"]}

	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	f.bundle = filepath.Join(base, "bundle")
	if err := os.Mkdir(f.bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.bundle, artifactFileName), binary, 0o700); err != nil {
		t.Fatal(err)
	}

	// master.key stand-in: 0600, owned by the server.
	f.secret = filepath.Join(base, "master.key")
	if err := os.WriteFile(f.secret, []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Probe socket stand-ins: the production layout (a 0770 directory and a
	// 0660 socket, both owned 65532:65532) and a bare 0660 socket in a
	// directory anyone can traverse, so the socket's own mode is tested too.
	// Without CAP_CHOWN the server keeps ownership and moves only the group,
	// to 65532 when it holds that group, as production's server does.
	ownerUID, gid := -1, os.Getegid()
	groups, _ := os.Getgroups()
	if os.Geteuid() == 0 {
		ownerUID, gid = probeGroupID, probeGroupID
	} else if slices.Contains(groups, probeGroupID) {
		gid = probeGroupID
	}
	probeRun := filepath.Join(base, "probe-run")
	if err := os.Mkdir(probeRun, 0o770); err != nil {
		t.Fatal(err)
	}
	for _, sock := range []string{filepath.Join(probeRun, "probe.sock"), filepath.Join(base, "bare.sock")} {
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		if err := os.Chmod(sock, 0o660); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(sock, ownerUID, gid); err != nil {
			t.Fatal(err)
		}
		f.sockets = append(f.sockets, sock)
	}
	if err := os.Chmod(probeRun, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(probeRun, ownerUID, gid); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f isolationFixture) loaded(id string, v2 bool) Loaded {
	l := Loaded{Manifest: Manifest{ID: id, Name: id, Type: TypeSystem, Capabilities: []string{"log:write"}}, Capabilities: []string{"log:write"}, BundlePath: f.bundle}
	if v2 {
		l.Manifest.Runtime = &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV2}
	}
	return l
}

func (f isolationFixture) request() isolationProbeRequest {
	return isolationProbeRequest{Sockets: f.sockets, Secret: f.secret, SetuidTo: uniqueInts(0, 100, f.serverUID), ServerPID: os.Getpid()}
}

func uniqueInts(values ...int) []int {
	slices.Sort(values)
	return slices.Compact(values)
}

type recordingLog struct {
	mu       sync.Mutex
	messages []string
}

func (l *recordingLog) Write(_ context.Context, e HostLogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, e.PluginID+": "+e.Message)
	return nil
}

func (l *recordingLog) pidOf(t *testing.T, pluginID string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		l.mu.Lock()
		for _, m := range l.messages {
			if rest, ok := strings.CutPrefix(m, pluginID+": isolation probe pid="); ok {
				l.mu.Unlock()
				pid, err := strconv.Atoi(rest)
				if err != nil {
					t.Fatal(err)
				}
				return pid
			}
		}
		l.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("%s never logged its pid", pluginID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func isolationRunner(t *testing.T, f isolationFixture, uids *PluginUIDRange, extra ...string) *SystemRunner {
	t.Helper()
	t.Setenv("LATTICE_TEST_ISOLATION_PROBE", "1")
	allow := append([]string{"LATTICE_TEST_ISOLATION_PROBE"}, extra...)
	r, err := NewSystemRunner(SystemRunnerOptions{
		RuntimeDir: f.runtimeDir, EnvAllowlist: allow, PluginUIDs: uids,
		StopGrace: 50 * time.Millisecond, CrashThreshold: 1000,
		Pool: &SystemPoolConfig{Size: 1, MaxOverflow: 0, StartTimeout: 10 * time.Second, MaxUses: 1000, MaxAge: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func startProbe(t *testing.T, r *SystemRunner, f isolationFixture, id string, generation uint64, v2 bool, log *recordingLog) {
	t.Helper()
	loaded := f.loaded(id, v2)
	broker := newTestBroker(t, id, []string{"log:write"}, HostServices{Log: log})
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: id, Generation: generation, Loaded: loaded, Broker: broker}); err != nil {
		t.Fatalf("start %s: %v", id, err)
	}
	t.Cleanup(func() {
		// Bounded: without CAP_KILL a dropped worker cannot be reaped and
		// an unbounded Stop would hang the test instead of failing it.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := r.Stop(ctx, RunnerStopRequest{PluginID: id}); err != nil {
			t.Errorf("stop %s: %v", id, err)
		}
	})
}

func invokeProbe(t *testing.T, r *SystemRunner, id string, generation uint64, req isolationProbeRequest) isolationReport {
	t.Helper()
	payload, _ := json.Marshal(req)
	rsp, err := r.Invoke(t.Context(), InvokeRequest{PluginID: id, Generation: generation, Action: "probe", Payload: payload})
	if err != nil || !rsp.OK {
		t.Fatalf("invoke %s: response=%+v err=%v", id, rsp, err)
	}
	var rep isolationReport
	if err := json.Unmarshal(rsp.Result, &rep); err != nil {
		t.Fatalf("decode %s report %s: %v", id, rsp.Result, err)
	}
	return rep
}

func assignedUID(t *testing.T, r *SystemRunner, id string) uint32 {
	t.Helper()
	uid, assigned, err := r.uids.assign(id)
	if err != nil || assigned {
		t.Fatalf("%s holds no uid yet: uid=%d assigned=%t err=%v", id, uid, assigned, err)
	}
	return uid
}

const zeroCaps = "0000000000000000"

// assertDropped checks everything design 30 promises about a dropped child.
func assertDropped(t *testing.T, path string, rep isolationReport, uid uint32, f isolationFixture) {
	t.Helper()
	u := strconv.FormatUint(uint64(uid), 10)
	want := u + " " + u + " " + u + " " + u
	if rep.Status["Uid"] != want || rep.Status["Gid"] != want {
		t.Fatalf("%s: Uid %q Gid %q, want %q for both", path, rep.Status["Uid"], rep.Status["Gid"], want)
	}
	if rep.Status["Groups"] != "" {
		t.Fatalf("%s: Groups %q, want none (the server's are %q)", path, rep.Status["Groups"], f.groupLine)
	}
	for _, set := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if rep.Status[set] != zeroCaps {
			t.Fatalf("%s: %s is %s, want an empty capability set", path, set, rep.Status[set])
		}
	}
	for target, got := range rep.Setuid {
		if got != syscall.EPERM.Error() {
			t.Fatalf("%s: setuid(%s) gave %q, want EPERM", path, target, got)
		}
	}
	for sock, got := range rep.Sockets {
		if got != syscall.EACCES.Error() {
			t.Fatalf("%s: opening the 0660 socket %s gave %q, want permission denied", path, sock, got)
		}
	}
	if rep.Secret != syscall.EACCES.Error() {
		t.Fatalf("%s: reading the server's 0600 file gave %q, want permission denied", path, rep.Secret)
	}
	if rep.ListCwd != syscall.EACCES.Error() || rep.WriteCwd != syscall.EACCES.Error() {
		t.Fatalf("%s: the 0711 working directory listed %q and took a write %q; want both denied", path, rep.ListCwd, rep.WriteCwd)
	}
	if rep.KillServer != syscall.EPERM.Error() {
		t.Fatalf("%s: signalling the server gave %q, want EPERM", path, rep.KillServer)
	}
	if rep.PtraceServer != "" && rep.PtraceServer != syscall.EPERM.Error() {
		t.Fatalf("%s: tracing the server gave %q, want EPERM", path, rep.PtraceServer)
	}
	if rep.HostCall != "ok" {
		t.Fatalf("%s: a host call across the drop gave %q, want ok", path, rep.HostCall)
	}
}

// assertUndropped checks that with the option unset the child is the
// server, exactly as before design 30.
func assertUndropped(t *testing.T, path string, rep isolationReport, f isolationFixture) {
	t.Helper()
	server := readProcStatus("self")
	if rep.Status["Uid"] != server["Uid"] || rep.Status["Gid"] != server["Gid"] || rep.Status["Groups"] != server["Groups"] {
		t.Fatalf("%s: child Uid %q Gid %q Groups %q, want the server's %q %q %q", path, rep.Status["Uid"], rep.Status["Gid"], rep.Status["Groups"], server["Uid"], server["Gid"], server["Groups"])
	}
	for sock, got := range rep.Sockets {
		if got != "ok" {
			t.Fatalf("%s: the undropped child could not open %s (%q); the stand-in proves nothing", path, sock, got)
		}
	}
	if rep.Secret != "ok" {
		t.Fatalf("%s: the undropped child could not read the 0600 file (%q); the stand-in proves nothing", path, rep.Secret)
	}
	if rep.KillServer != "ok" || rep.HostCall != "ok" {
		t.Fatalf("%s: undropped kill=%q host call=%q, want both ok", path, rep.KillServer, rep.HostCall)
	}
}

func TestPluginUIDDropConfinesV1AndV2Children(t *testing.T) {
	requireUIDDrop(t)
	f := newIsolationFixture(t)
	log := &recordingLog{}
	r := isolationRunner(t, f, &PluginUIDRange{Base: 200000, Size: 64})
	startProbe(t, r, f, "p.iso-v1", 1, false, log)
	startProbe(t, r, f, "p.iso-v2", 1, true, log)

	req := f.request()
	req.TryPtrace = true
	assertDropped(t, "v1 invocation", invokeProbe(t, r, "p.iso-v1", 1, req), assignedUID(t, r, "p.iso-v1"), f)
	v2 := invokeProbe(t, r, "p.iso-v2", 1, req)
	assertDropped(t, "v2 worker", v2, assignedUID(t, r, "p.iso-v2"), f)
	if v2.Cwd != filepath.Join(f.runtimeDir, "p.iso-v2", "generation-1") {
		t.Fatalf("v2 worker ran in %q, want its generation directory", v2.Cwd)
	}
	if v1, v2 := assignedUID(t, r, "p.iso-v1"), assignedUID(t, r, "p.iso-v2"); v1 == v2 {
		t.Fatalf("two plugins share uid %d", v1)
	}
}

func TestPluginUIDUnsetKeepsChildrenOnTheServerIdentity(t *testing.T) {
	requireUIDDrop(t)
	f := newIsolationFixture(t)
	log := &recordingLog{}
	r := isolationRunner(t, f, nil)
	startProbe(t, r, f, "p.same-v1", 1, false, log)
	startProbe(t, r, f, "p.same-v2", 1, true, log)
	assertUndropped(t, "v1 invocation", invokeProbe(t, r, "p.same-v1", 1, f.request()), f)
	assertUndropped(t, "v2 worker", invokeProbe(t, r, "p.same-v2", 1, f.request()), f)
}

// A plugin cannot signal or trace a sibling plugin on another uid.
func TestPluginUIDDropSeparatesSiblings(t *testing.T) {
	requireUIDDrop(t)
	f := newIsolationFixture(t)
	log := &recordingLog{}
	r := isolationRunner(t, f, &PluginUIDRange{Base: 200000, Size: 64})
	startProbe(t, r, f, "p.sibling-a", 1, false, log)
	startProbe(t, r, f, "p.sibling-b", 1, true, log)
	sibling := invokeProbe(t, r, "p.sibling-b", 1, isolationProbeRequest{})
	req := f.request()
	req.SiblingPID, req.TryPtrace = sibling.PID, true
	rep := invokeProbe(t, r, "p.sibling-a", 1, req)
	if rep.KillSibling != syscall.EPERM.Error() || rep.PtraceSibling != syscall.EPERM.Error() {
		t.Fatalf("plugin a reached plugin b (pid %d): kill=%q ptrace=%q, want EPERM for both", sibling.PID, rep.KillSibling, rep.PtraceSibling)
	}
	// Plugin b is untouched and still serves.
	if again := invokeProbe(t, r, "p.sibling-b", 1, isolationProbeRequest{}); again.PID != sibling.PID {
		t.Fatalf("plugin b's worker changed from %d to %d", sibling.PID, again.PID)
	}
}

// The server reaps a dropped child that ignores SIGTERM, through the v1
// timeout path and the v2 worker teardown, which takes CAP_KILL across the
// uid boundary.
func TestPluginUIDDropTeardownCrossesTheUIDBoundary(t *testing.T) {
	requireUIDDrop(t)
	f := newIsolationFixture(t)
	log := &recordingLog{}
	r := isolationRunner(t, f, &PluginUIDRange{Base: 200000, Size: 64}, "LATTICE_TEST_PROBE_IGNORE_TERM")
	t.Setenv("LATTICE_TEST_PROBE_IGNORE_TERM", "1")

	startProbe(t, r, f, "p.hang-v1", 1, false, log)
	payload, _ := json.Marshal(isolationProbeRequest{HangAfterLog: true})
	// The invocation returns only once the child's group is extinct, so it
	// never returns if the kill cannot cross the uid; bound the wait.
	done := make(chan error, 1)
	go func() {
		_, err := r.Invoke(context.Background(), InvokeRequest{PluginID: "p.hang-v1", Generation: 1, Action: "probe", Payload: payload,
			Constraints: InvokeConstraints{Budget: &InvokeBudgetSpec{TimeoutMS: 3000, StdoutBytes: 1 << 20, StderrBytes: 1 << 16, HostCalls: 8}}})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("a hung v1 child must time out, got %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the server did not reap the hung dropped v1 child (pid %d) within 30s: the kill did not cross the uid", log.pidOf(t, "p.hang-v1"))
	}
	pid := log.pidOf(t, "p.hang-v1")
	assertGone(t, "v1 child", pid)

	startProbe(t, r, f, "p.hang-v2", 1, true, log)
	worker := invokeProbe(t, r, "p.hang-v2", 1, isolationProbeRequest{})
	if worker.Status["Uid"] == readProcStatus("self")["Uid"] {
		t.Fatalf("the v2 worker was not dropped: %q", worker.Status["Uid"])
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := r.Stop(ctx, RunnerStopRequest{PluginID: "p.hang-v2"}); err != nil {
		t.Fatalf("stopping the dropped v2 worker: %v", err)
	}
	assertGone(t, "v2 worker", worker.PID)
}

func assertGone(t *testing.T, what string, pid int) {
	t.Helper()
	if pid <= 0 {
		t.Fatalf("%s: no pid", what)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("%s %d survived teardown: kill(0) gave %v", what, pid, err)
	}
	if processGroupExists(pid) {
		t.Fatalf("%s %d: its process group survived teardown", what, pid)
	}
}

// With CAP_CHOWN (root), every owner mutation in the staged chain is made
// for real and refused, beside the mode checks the portable test covers.
func TestStagedChainRefusesARealOwnerChange(t *testing.T) {
	requireRoot(t, "changing an owner needs root")
	f := newIsolationFixture(t)
	log := &recordingLog{}
	r := isolationRunner(t, f, &PluginUIDRange{Base: 200000, Size: 64})
	startProbe(t, r, f, "p.owner", 1, false, log)
	genDir := filepath.Join(f.runtimeDir, "p.owner", "generation-1")
	artifact := filepath.Join(genDir, "artifact")
	plugin := assignedUID(t, r, "p.owner")
	for _, path := range []string{f.runtimeDir, filepath.Join(f.runtimeDir, "p.owner"), genDir, artifact} {
		for _, owner := range []int{int(plugin), 12345} {
			if err := os.Lchown(path, owner, -1); err != nil {
				t.Fatal(err)
			}
			_, err := r.Invoke(t.Context(), InvokeRequest{PluginID: "p.owner", Generation: 1, Action: "probe", Payload: json.RawMessage(`{}`)})
			if !errors.Is(err, errStagedArtifactChanged) || !strings.Contains(err.Error(), "owned by uid") {
				t.Fatalf("%s owned by %d: got %v, want a refusal", path, owner, err)
			}
			if err := os.Lchown(path, 0, -1); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The restored chain serves again, still dropped.
	rep := invokeProbe(t, r, "p.owner", 1, f.request())
	assertDropped(t, "after restoring the owners", rep, plugin, f)
}
