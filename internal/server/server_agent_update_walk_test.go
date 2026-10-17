package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// walkTestBinary is a stand-in agent: a shell script that answers -version
// and -compat-json the way the real binary does, padded to size with text
// that compresses about as well as a Go binary. The padding sits after exit,
// so sh never parses it.
func walkTestBinary(version string, size int) ([]byte, string) {
	head := "#!/bin/sh\ncase \"$1\" in\n  -version) echo " + version + " ;;\n  -compat-json) echo '{}' ;;\nesac\nexit 0\n"
	words := []string{"lattice", "agent", "node", "plan", "lease", "digest", "range", "budget", "source", "mirror", "0x7f", "runtime", "syscall", "goroutine"}
	rng := rand.New(rand.NewSource(int64(size)))
	var b strings.Builder
	b.WriteString(head)
	for b.Len() < size {
		if rng.Intn(4) == 0 {
			fmt.Fprintf(&b, "%08x", rng.Uint32())
		} else {
			b.WriteString(words[rng.Intn(len(words))])
		}
		if rng.Intn(12) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}
	data := []byte(b.String()[:size])
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:])
}

// seedWalkUpdate is seedControlPlaneUpdate for a binary the script can run:
// the artifact is stored raw or, as an import stores it, gzip-compressed, the
// policy pins the release URL as the fallback, and the approval is approved
// with its apply task leased to the node.
func seedWalkUpdate(t *testing.T, srv *Server, st *store.Store, data []byte, compressed bool) (agentArtifactRef, model.Approval, model.Task) {
	t.Helper()
	seedLinuxAgentNode(t, st)
	sum := sha256.Sum256(data)
	ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: hex.EncodeToString(sum[:])}
	put := srv.storeAgentArtifact
	if compressed {
		put = srv.storeCompressedAgentArtifact
	}
	view, err := put(ref, data)
	if err != nil {
		t.Fatalf("store artifact: %v", err)
	}
	ref.GzipSHA256 = view.CompressedSHA256
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.4",
		BinaryURL: fallbackTestReleaseURL, SHA256: ref.SHA256,
		InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{
		ID: id.New("task"), ApprovalID: approval.ID, Targets: []string{"node-a"},
		Interpreter: "sh", Script: "true", TimeoutSec: 600, OutputLimit: 65536,
		Status: model.TaskQueued, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	leased, err := st.LeaseTasks("node-a", 1)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease the apply task: %v %d", err, len(leased))
	}
	task, _ := st.Task(leased[0].ID)
	return ref, approval, task
}

// walkScript renders the apply script for an approval with its payload
// changed by mutate, under the plan the approval carries.
func walkScript(t *testing.T, approval model.Approval, mutate func(p *agentUpdatePayload)) (string, agentUpdatePayload) {
	t.Helper()
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&payload)
		approval.Action = agentUpdateApprovalAction(payload)
	}
	script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "\nfetch_one() {\n") {
		t.Fatalf("a plan made now must render the source walk:\n%s", script)
	}
	return script, payload
}

// walkRun describes one run of a whole rendered apply script under sh. The
// script runs as rendered except for what a test machine needs: PATH holds
// only the tools named here, TARGET points into the run's own directory,
// systemd's runtime directory is a directory of the run's, and systemctl and
// systemd-run are stubs that log their arguments.
//
// With stub fetchers, each source answers per call from a list of
// exit:cut:took steps (the last one repeats): the exit status, the byte of
// its body at which it stops sending (0 for none, -1 to send nothing, as curl
// does when it refuses a range it cannot use), and the seconds the call moves
// the stub clock on. A stub given -C - or -c continues its output file.
type walkRun struct {
	fetcher          string
	real             bool
	caFile           string
	cpURL, fbURL     string
	cpBody, fbBody   []byte
	cpSteps, fbSteps string
	// clock is "" for the stub clock, which starts at 1000 and moves only
	// when a stub fetch or sleep says so, "no-epoch" for a date that prints
	// %s literally, and "host" for the host's date and sleep.
	clock     string
	timeout   bool
	noGzip    bool
	overrides map[string]string
	// kept seeds files in the install directory, by name.
	kept           map[string][]byte
	serviceMissing bool
	noSystemd      bool
	env            []string
}

type walkOutcome struct {
	exit           int
	stdout, stderr string
	calls          []string
	installDir     string
	installed      []byte
	summary        string
}

func (o walkOutcome) kept(name string) ([]byte, bool) {
	data, err := os.ReadFile(filepath.Join(o.installDir, name))
	return data, err == nil
}

// fetches returns the logged calls of one fetcher, in order.
func (o walkOutcome) fetches(fetcher string) []string {
	var out []string
	for _, call := range o.calls {
		if strings.HasPrefix(call, fetcher+" ") {
			out = append(out, call)
		}
	}
	return out
}

const walkFetchStub = `#!/bin/sh
name=${0##*/}
if [ "$1" = --help ]; then
  if [ -z "$STUB_BUSYBOX" ]; then echo '       --https-only                only follow secure links'; fi
  exit 0
fi
out=''; prev=''; last=''; resume=0
for a in "$@"; do
  if [ "$prev" = -o ] || [ "$prev" = -O ]; then out=$a; fi
  if [ "$prev" = -C ] && [ "$a" = - ]; then resume=1; fi
  if [ "$a" = -c ]; then resume=1; fi
  prev=$a; last=$a
done
printf '%s %s\n' "$name" "$*" >>"$STUB_CALLS"
case "$last" in
  "$STUB_CP_URL") src=cp; body=$STUB_CP_BODY; steps=$STUB_CP_STEPS ;;
  "$STUB_FB_URL") src=fb; body=$STUB_FB_BODY; steps=$STUB_FB_STEPS ;;
  *) echo "stub: unexpected url $last" >&2; exit 97 ;;
esac
n=1
if [ -f "$STUB_DIR/count.$src" ]; then n=$(($(cat "$STUB_DIR/count.$src") + 1)); fi
echo "$n" >"$STUB_DIR/count.$src"
if [ -z "$steps" ]; then steps=0:0:1; fi
step=$(echo "$steps" | awk -v n="$n" '{ if (n > NF) n = NF; print $n }')
code=${step%%:*}; rest=${step#*:}; cut=${rest%%:*}; took=${rest#*:}
if [ "$cut" -ge 0 ] && [ -r "$body" ]; then
  from=0
  if [ "$resume" = 1 ] && [ -f "$out" ]; then from=$(($(wc -c <"$out"))); else : >"$out"; fi
  end=$(($(wc -c <"$body")))
  if [ "$cut" -gt 0 ] && [ "$cut" -lt "$end" ]; then end=$cut; fi
  if [ "$end" -gt "$from" ]; then tail -c +$((from + 1)) "$body" | head -c $((end - from)) >>"$out"; fi
fi
echo $(($(cat "$STUB_CLOCK") + took)) >"$STUB_CLOCK"
if [ "$code" != 0 ]; then echo "stub: ($code) failed" >&2; fi
exit "$code"
`

func runWalkScript(t *testing.T, script string, r walkRun) walkOutcome {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	installDir := filepath.Join(dir, "install")
	systemdDir := filepath.Join(dir, "run-systemd")
	for _, d := range []string{bin, installDir, systemdDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if r.noSystemd {
		if err := os.Remove(systemdDir); err != nil {
			t.Fatal(err)
		}
	}
	calls := filepath.Join(dir, "calls")
	clock := filepath.Join(dir, "clock")
	if err := os.WriteFile(clock, []byte("1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tools := []string{"cat", "rm", "awk", "sha256sum", "shasum", "dirname", "mkdir", "chmod", "wc", "tail", "head", "sed", "grep", "cp", "mv", "install", "readlink", "true"}
	if r.real {
		tools = append(tools, r.fetcher)
	}
	if r.clock == "host" {
		tools = append(tools, "date", "sleep")
	}
	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err != nil {
			if tool == r.fetcher {
				t.Skipf("no %s on this host", tool)
			}
			continue
		}
		if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	stubs := map[string]string{
		"systemctl": "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >>\"$STUB_CALLS\"\n" +
			"if [ \"$STUB_SERVICE_MISSING\" = 1 ]; then case \"$1\" in status) exit 4 ;; --no-legend) exit 0 ;; esac; fi\n" +
			"case \"$1\" in --no-legend) echo 'lattice-agent.service enabled' ;; esac\nexit 0\n",
		"systemd-run": "#!/bin/sh\nprintf 'systemd-run %s\\n' \"$*\" >>\"$STUB_CALLS\"\nexit 0\n",
	}
	if !r.real {
		stubs[r.fetcher] = walkFetchStub
	}
	switch r.clock {
	case "":
		stubs["date"] = "#!/bin/sh\ncat \"$STUB_CLOCK\"\n"
		stubs["sleep"] = "#!/bin/sh\nprintf 'sleep %s\\n' \"$1\" >>\"$STUB_CALLS\"\necho $(($(cat \"$STUB_CLOCK\") + $1)) >\"$STUB_CLOCK\"\n"
	case "no-epoch":
		stubs["date"] = "#!/bin/sh\necho '%s'\n"
		stubs["sleep"] = "#!/bin/sh\nprintf 'sleep %s\\n' \"$1\" >>\"$STUB_CALLS\"\n"
	case "host":
	default:
		t.Fatalf("unknown clock %q", r.clock)
	}
	// gzip and timeout log how they were called and run the host's own, so a
	// test can tell the probe from a decompression and see the limit wget
	// ran under.
	wrap := func(name string) {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("no %s on this host", name)
		}
		stubs[name] = "#!/bin/sh\nprintf '" + name + " %s\\n' \"$*\" >>\"$STUB_CALLS\"\nexec " + shellQuote(path) + " \"$@\"\n"
	}
	if !r.noGzip {
		wrap("gzip")
	}
	if r.timeout {
		if r.real {
			wrap("timeout")
		} else {
			stubs["timeout"] = "#!/bin/sh\nprintf 'timeout %s\\n' \"$*\" >>\"$STUB_CALLS\"\nshift\nexec \"$@\"\n"
		}
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cpBody, fbBody := filepath.Join(dir, "cp-body"), filepath.Join(dir, "fb-body")
	for path, body := range map[string][]byte{cpBody: r.cpBody, fbBody: r.fbBody} {
		if body != nil {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, body := range r.kept {
		if err := os.WriteFile(filepath.Join(installDir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	target := filepath.Join(installDir, "lattice-agent")
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "PATH="):
			lines[i] = "PATH=" + shellQuote(bin)
		case strings.HasPrefix(line, "TARGET="):
			lines[i] = "TARGET=" + shellQuote(target)
		case r.real && strings.HasPrefix(line, "URL="):
			lines[i] = "URL=" + shellQuote(r.cpURL)
		case r.real && strings.HasPrefix(line, "FALLBACK_URL="):
			lines[i] = "FALLBACK_URL=" + shellQuote(r.fbURL)
		}
		for name, value := range r.overrides {
			if strings.HasPrefix(line, name+"=") {
				lines[i] = name + "=" + value
			}
		}
	}
	text := strings.ReplaceAll(strings.Join(lines, "\n"), "/run/systemd/system", systemdDir)
	scriptFile := filepath.Join(dir, "apply.sh")
	if err := os.WriteFile(scriptFile, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", scriptFile)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + bin,
		"LATTICE_TASK_ID=task-1",
		"LATTICE_TASK_LEASE_ID=lease-1",
		"STUB_DIR=" + dir,
		"STUB_CALLS=" + calls,
		"STUB_CLOCK=" + clock,
		"STUB_CP_URL=" + r.cpURL,
		"STUB_FB_URL=" + r.fbURL,
		"STUB_CP_BODY=" + cpBody,
		"STUB_FB_BODY=" + fbBody,
		"STUB_CP_STEPS=" + r.cpSteps,
		"STUB_FB_STEPS=" + r.fbSteps,
	}
	if r.serviceMissing {
		cmd.Env = append(cmd.Env, "STUB_SERVICE_MISSING=1")
	}
	if r.real {
		wgetrc := filepath.Join(dir, "wgetrc")
		if err := os.WriteFile(wgetrc, []byte("ca_certificate = "+r.caFile+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd.Env = append(cmd.Env, "CURL_CA_BUNDLE="+r.caFile, "WGETRC="+wgetrc)
	}
	cmd.Env = append(cmd.Env, r.env...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := walkOutcome{stdout: stdout.String(), stderr: stderr.String(), installDir: installDir}
	if exitErr, ok := err.(*exec.ExitError); ok {
		out.exit = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(calls); err == nil {
		out.calls = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	out.installed, _ = os.ReadFile(target)
	out.summary, _ = parseAgentFetchSummary(out.stderr)
	return out
}

// The walk's plan line states the numbers the script uses, and every plan
// made now carries it.
func TestAgentUpdatePlanStatesTheSourceWalk(t *testing.T) {
	if rate, _ := strconv.Atoi(agentFetchCutRate); rate != 32*1024 {
		t.Fatalf("the plan says 32 KiB/s and the script cuts at %s B/s", agentFetchCutRate)
	}
	for _, want := range []string{
		"of the " + agentFetchBudgetSec + " s download budget",
		"under 32 KiB/s for " + agentFetchCutWindow + " s",
		"with " + agentFetchConnectSec + " s or more left",
		"retried up to " + agentFetchRetries + " times",
		"ends with a lattice-agent-fetch line",
	} {
		if !strings.Contains(agentUpdateCutoffPlanLine, want) {
			t.Fatalf("the cutoff line must say %q:\n%s", want, agentUpdateCutoffPlanLine)
		}
	}
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	if !strings.Contains(approval.Plan, "\n"+agentUpdateCutoffPlanLine+"\n") {
		t.Fatalf("a plan made now must carry the cutoff line:\n%s", approval.Plan)
	}
	script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\nFETCH_BUDGET=" + agentFetchBudgetSec + "\n",
		"\nFETCH_CONNECT=" + agentFetchConnectSec + "\n",
		"\nFETCH_CUT_RATE=" + agentFetchCutRate + "\n",
		"\nFETCH_CUT_WINDOW=" + agentFetchCutWindow + "\n",
		"\nFETCH_RETRIES=" + agentFetchRetries + "\n",
		"\nFETCH_PAUSE=" + agentFetchRetryPause + "\n",
		"\ntrap 'fetch_summary \"$?\"' EXIT\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("the walk must use the stated value %q:\n%s", strings.TrimSpace(want), script)
		}
	}
	// The summary is armed before the systemd checks, so every exit path
	// after the variables prints it.
	if strings.Index(script, "trap 'fetch_summary") > strings.Index(script, "systemd is required for managed agent updates") {
		t.Fatalf("the summary must be armed before the first check that can exit:\n%s", script)
	}
}

// The approved script names one lease-carrying line per fetcher, on the
// control-plane source, and that line never follows a redirect. Every other
// fetch follows redirects only to HTTPS and carries no credential.
func TestAgentUpdateWalkSendsTheLeaseOnlyToTheControlPlane(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 8192)
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed=%t", compressed), func(t *testing.T) {
			srv, _, st = newAgentArtifactServer(t)
			_, approval, _ := seedWalkUpdate(t, srv, st, data, compressed)
			script, _ := walkScript(t, approval, nil)
			leased := 0
			for _, line := range strings.Split(script, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "curl ") && !strings.HasPrefix(line, "fetch_bounded wget ") {
					continue
				}
				if strings.Contains(line, agentTaskLeaseHeader) {
					leased++
					if !strings.HasSuffix(line, " \"$URL\"") || strings.Contains(line, "curl -fsSL") ||
						(strings.Contains(line, "wget ") && !strings.Contains(line, "--max-redirect=0")) {
						t.Fatalf("the lease must go only to the control plane, which is never followed through a redirect: %s", line)
					}
					continue
				}
				if !strings.HasSuffix(line, " \"$FALLBACK_URL\"") {
					t.Fatalf("a fetch without the lease must be the fallback: %s", line)
				}
				if strings.HasPrefix(line, "curl ") && !strings.Contains(line, "--proto '=https'") {
					t.Fatalf("the fallback follows redirects to HTTPS only: %s", line)
				}
			}
			if leased != 2 {
				t.Fatalf("want one leased curl line and one leased wget line, found %d:\n%s", leased, script)
			}
		})
	}
}

// A slow source is left within its window with its bytes kept, the next
// source continues the same file, every source is cut, the last included,
// and the second pass goes, uncut, to the source that delivered the most.
func TestAgentUpdateWalkLeavesASlowSourceAndGivesTheRestToTheBest(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 8192)
	_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
	script, payload := walkScript(t, approval, nil)
	run := func(t *testing.T, r walkRun) walkOutcome {
		t.Helper()
		r.fetcher, r.cpURL, r.fbURL, r.cpBody, r.fbBody = "curl", payload.BinaryURL, payload.FallbackURL, data, data
		return runWalkScript(t, script, r)
	}

	t.Run("the control plane delivered more", func(t *testing.T) {
		o := run(t, walkRun{cpSteps: "28:1000:30 0:0:5", fbSteps: "28:1500:30"})
		if o.exit != 0 || !bytes.Equal(o.installed, data) {
			t.Fatalf("exit %d, installed %d bytes, stderr:\n%s", o.exit, len(o.installed), o.stderr)
		}
		curls := o.fetches("curl")
		if len(curls) != 3 {
			t.Fatalf("want the control plane, the fallback, then the second pass, got %q", curls)
		}
		for i, want := range []string{
			"--max-time 240 --speed-limit 32768 --speed-time 30 ",
			"--max-time 450 --speed-limit 32768 --speed-time 30 ",
			"--max-time 420 --speed-limit 0 --speed-time 30 ",
		} {
			if !strings.Contains(curls[i], want) {
				t.Fatalf("fetch %d must run with %q: %s", i+1, want, curls[i])
			}
		}
		if !strings.HasSuffix(curls[2], payload.BinaryURL) || !strings.Contains(curls[2], "lease-1") {
			t.Fatalf("the second pass must return to the control plane, with its lease: %s", curls[2])
		}
		want := fmt.Sprintf("lattice-agent-fetch v1 1:cp:28:1000:30 2:up:28:500:30 p2:cp:0:%d:5 result:0:done", len(data)-1500)
		if o.summary != want {
			t.Fatalf("summary %q, want %q, stderr:\n%s", o.summary, want, o.stderr)
		}
	})
	t.Run("the fallback delivered more", func(t *testing.T) {
		o := run(t, walkRun{cpSteps: "28:300:30", fbSteps: "28:2000:30 0:0:7"})
		curls := o.fetches("curl")
		if o.exit != 0 || len(curls) != 3 || !strings.HasSuffix(curls[2], payload.FallbackURL) ||
			strings.Contains(curls[2], "lease-1") || !strings.Contains(curls[2], "--speed-limit 0 ") {
			t.Fatalf("the second pass must go to the fallback, uncut and without the lease: exit %d calls %q stderr:\n%s", o.exit, curls, o.stderr)
		}
	})
	t.Run("the equal share", func(t *testing.T) {
		// A source that stays above the cutoff still stops at its share, and
		// the next gets what is left.
		o := run(t, walkRun{cpSteps: "28:2000:240", fbSteps: "0:0:10"})
		curls := o.fetches("curl")
		if o.exit != 0 || len(curls) != 2 || !strings.Contains(curls[1], "--max-time 240 --speed-limit 32768 ") {
			t.Fatalf("the fallback must get what the control plane's share left, still cut: exit %d calls %q", o.exit, curls)
		}
	})
	t.Run("no clock", func(t *testing.T) {
		// Without epoch seconds every fetch is charged its whole share, so
		// the walk cannot outrun the budget, and the summary says so.
		o := run(t, walkRun{clock: "no-epoch", cpSteps: "18:500:0", fbSteps: "18:800:0"})
		curls := o.fetches("curl")
		if o.exit != 18 || len(curls) != 2 || !strings.Contains(curls[1], "--max-time 240 ") {
			t.Fatalf("exit %d calls %q stderr:\n%s", o.exit, curls, o.stderr)
		}
		if o.summary != "lattice-agent-fetch v1 1:cp:18:500:- 2:up:18:300:- result:18:fetch" {
			t.Fatalf("summary %q", o.summary)
		}
		if kept, ok := o.kept(agentUpdatePartialPrefix + payload.SHA256); !ok || !bytes.Equal(kept, data[:800]) {
			t.Fatalf("the bytes both sources delivered must be kept, have %d", len(kept))
		}
	})
	t.Run("a source that delivered nothing is not retried", func(t *testing.T) {
		o := run(t, walkRun{cpSteps: "7:-1:20", fbSteps: "22:-1:1"})
		if o.exit != 22 || len(o.fetches("curl")) != 2 || len(o.fetches("sleep")) != 0 {
			t.Fatalf("exit %d calls %q", o.exit, o.calls)
		}
	})
}

// curl's 33 means the source ignored the range. The walk moves on and keeps
// the partial for a source that can continue it, and deletes it only when
// every source the attempt reached refused.
func TestAgentUpdateWalkKeepsAPartialPastASourceThatIgnoresRanges(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 8192)
	_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
	script, payload := walkScript(t, approval, nil)
	partial := agentUpdatePartialPrefix + payload.SHA256
	run := func(t *testing.T, script string, r walkRun) walkOutcome {
		t.Helper()
		r.fetcher, r.cpURL, r.fbURL, r.cpBody, r.fbBody = "curl", payload.BinaryURL, payload.FallbackURL, data, data
		r.kept = map[string][]byte{partial: data[:1000]}
		return runWalkScript(t, script, r)
	}
	o := run(t, script, walkRun{cpSteps: "33:-1:1", fbSteps: "0:0:2"})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("the fallback must continue the kept partial: exit %d stderr:\n%s", o.exit, o.stderr)
	}
	if want := fmt.Sprintf("lattice-agent-fetch v1 1:cp:33:0:1 2:up:0:%d:2 result:0:done", len(data)-1000); o.summary != want {
		t.Fatalf("summary %q, want %q", o.summary, want)
	}
	// A complete kept file is checked, not fetched: curl 7 answers the 416
	// for a range past its end with exit 22, which would fail every attempt.
	r := walkRun{fetcher: "curl", cpURL: payload.BinaryURL, fbURL: payload.FallbackURL, cpBody: data, fbBody: data,
		cpSteps: "22:-1:1", fbSteps: "22:-1:1", kept: map[string][]byte{partial: data}}
	if o := runWalkScript(t, script, r); o.exit != 0 || !bytes.Equal(o.installed, data) || len(o.fetches("curl")) != 0 ||
		o.summary != "lattice-agent-fetch v1 result:0:done" || !strings.Contains(o.stdout, "is already complete") {
		t.Fatalf("a complete kept file must install without a fetch: exit %d calls %q summary %q", o.exit, o.calls, o.summary)
	}
	o = run(t, script, walkRun{cpSteps: "33:-1:1", fbSteps: "33:-1:1"})
	if _, ok := o.kept(partial); o.exit != 33 || ok {
		t.Fatalf("a partial every source refused to continue must go: exit %d kept %t", o.exit, ok)
	}
	single, _ := walkScript(t, approval, func(p *agentUpdatePayload) { p.FallbackURL = "" })
	o = run(t, single, walkRun{cpSteps: "33:-1:1"})
	if _, ok := o.kept(partial); o.exit != 33 || ok || len(o.fetches("curl")) != 1 {
		t.Fatalf("a single source that refused must drop the partial and not retry: exit %d kept %t calls %q", o.exit, ok, o.calls)
	}
}

// With one source there is nothing to switch to, so it runs uncut and the
// second pass is its retry: one fetch for what is left and up to three more
// after a transient failure, two seconds apart, and none after a definite
// one.
func TestAgentUpdateWalkRetriesASingleSourceWithoutTheCutoff(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 8192)
	_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
	for name, mutate := range map[string]func(p *agentUpdatePayload){
		"control plane": func(p *agentUpdatePayload) { p.FallbackURL = "" },
		"upstream": func(p *agentUpdatePayload) {
			p.BinarySource, p.BinaryURL, p.FallbackURL = agentBinarySourceUpstream, fallbackTestReleaseURL, ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			script, payload := walkScript(t, approval, mutate)
			run := func(steps string) walkOutcome {
				return runWalkScript(t, script, walkRun{fetcher: "curl", cpURL: payload.BinaryURL, cpBody: data, cpSteps: steps})
			}
			o := run("18:500:10 18:1000:10 18:1500:10 18:2000:10 18:2500:10")
			curls := o.fetches("curl")
			if o.exit != 18 || len(curls) != 5 || len(o.fetches("sleep")) != 3 {
				t.Fatalf("want the first fetch, the second pass and its three retries: exit %d calls %q", o.exit, o.calls)
			}
			for i, want := range []string{"--max-time 480 ", "--max-time 470 ", "--max-time 458 ", "--max-time 446 ", "--max-time 434 "} {
				if !strings.Contains(curls[i], want) || !strings.Contains(curls[i], "--speed-limit 0 ") {
					t.Fatalf("fetch %d must be uncut with %q: %s", i+1, want, curls[i])
				}
			}
			kind := agentUpdateFetchSources(payload)[0].kind
			if want := "lattice-agent-fetch v1 1:" + kind + ":18:500:10" + strings.Repeat(" p2:"+kind+":18:500:10", 4) + " result:18:fetch"; o.summary != want {
				t.Fatalf("summary %q, want %q", o.summary, want)
			}
			if kept, ok := o.kept(agentUpdatePartialPrefix + payload.SHA256); !ok || !bytes.Equal(kept, data[:2500]) {
				t.Fatalf("what the attempt received must be kept, have %d bytes", len(kept))
			}
			if !strings.Contains(o.stderr, "kept the 2500 bytes of the download received so far") {
				t.Fatalf("the output must say what was kept, stderr:\n%s", o.stderr)
			}
			o = run("18:500:10 0:0:10")
			if o.exit != 0 || !bytes.Equal(o.installed, data) {
				t.Fatalf("a retry that finishes installs: exit %d stderr:\n%s", o.exit, o.stderr)
			}
			o = run("18:500:10 22:-1:1")
			if o.exit != 22 || len(o.fetches("curl")) != 2 {
				t.Fatalf("an HTTP error is not retried: exit %d calls %q", o.exit, o.calls)
			}
		})
	}
}

// wget has no speed cutoff and no second pass. Each source runs inside what
// is left of the budget when timeout exists, and once.
func TestAgentUpdateWalkWithWget(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 8192)
	_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
	script, payload := walkScript(t, approval, nil)
	run := func(r walkRun) walkOutcome {
		r.fetcher, r.cpURL, r.fbURL, r.cpBody, r.fbBody = "wget", payload.BinaryURL, payload.FallbackURL, data, data
		return runWalkScript(t, script, r)
	}
	o := run(walkRun{timeout: true, cpSteps: "4:500:50", fbSteps: "0:0:10"})
	if o.exit != 0 || !bytes.Equal(o.installed, data) {
		t.Fatalf("exit %d stderr:\n%s", o.exit, o.stderr)
	}
	var bounded []string
	for _, call := range o.calls {
		if strings.HasPrefix(call, "timeout ") && !strings.HasPrefix(call, "timeout 5 true") {
			bounded = append(bounded, call)
		}
	}
	if len(bounded) != 2 || !strings.HasPrefix(bounded[0], "timeout 480 wget ") || !strings.HasPrefix(bounded[1], "timeout 430 wget ") {
		t.Fatalf("each wget must run inside what is left of the budget: %q", bounded)
	}
	for _, call := range o.fetches("wget") {
		if strings.Contains(call, "speed") {
			t.Fatalf("wget has no speed cutoff: %s", call)
		}
	}
	if want := fmt.Sprintf("lattice-agent-fetch v1 1:cp:4:500:50 2:up:0:%d:10 result:0:done", len(data)-500); o.summary != want {
		t.Fatalf("summary %q, want %q", o.summary, want)
	}
	o = run(walkRun{timeout: true, cpSteps: "4:500:50", fbSteps: "8:-1:1"})
	if o.exit != 8 || len(o.fetches("wget")) != 2 {
		t.Fatalf("wget makes no second pass: exit %d calls %q", o.exit, o.calls)
	}
	o = run(walkRun{cpSteps: "4:500:50", fbSteps: "0:0:10"})
	if o.exit != 0 || len(o.fetches("timeout")) != 0 {
		t.Fatalf("without timeout wget runs as before: exit %d calls %q", o.exit, o.calls)
	}
	// busybox wget cannot refuse plain HTTP or a redirect, so it never
	// fetches, and the task says why.
	o = run(walkRun{env: []string{"STUB_BUSYBOX=1"}})
	if o.exit != 1 || len(o.fetches("wget")) != 0 || o.summary != "lattice-agent-fetch v1 result:1:fetch" ||
		!strings.Contains(o.stderr, "the update needs curl or GNU wget") {
		t.Fatalf("exit %d calls %q summary %q stderr:\n%s", o.exit, o.calls, o.summary, o.stderr)
	}
}

// The summary line ends every exit path, carries the stage the script
// stopped in, and parses.
func TestAgentUpdateWalkSummaryOnEveryExitPath(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 8192)
	_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
	script, payload := walkScript(t, approval, nil)
	wrongVersion, _ := walkTestBinary("9.9.9", 8192)
	for _, tc := range []struct {
		name string
		run  walkRun
		want string
		exit int
	}{
		{"installed", walkRun{cpBody: data}, fmt.Sprintf("lattice-agent-fetch v1 1:cp:0:%d:1 result:0:done", len(data)), 0},
		{"no systemd", walkRun{cpBody: data, noSystemd: true}, "lattice-agent-fetch v1 result:1:prepare", 1},
		{"missing service", walkRun{cpBody: data, serviceMissing: true}, "lattice-agent-fetch v1 result:1:prepare", 1},
		{"digest failure", walkRun{cpBody: wrongVersion}, fmt.Sprintf("lattice-agent-fetch v1 1:cp:0:%d:1 result:1:verify", len(data)), 1},
		{"version mismatch", walkRun{cpBody: data}, "", 1},
		{"no fetcher", walkRun{cpBody: data}, "lattice-agent-fetch v1 result:1:fetch", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.run
			r.fetcher, r.cpURL, r.fbURL = "curl", payload.BinaryURL, payload.FallbackURL
			s := script
			switch tc.name {
			case "version mismatch":
				// The pinned digest is the wrong version's, so the digest
				// passes and the version check is what stops it.
				sum := sha256.Sum256(wrongVersion)
				s = strings.Replace(s, "EXPECT_SHA='"+payload.SHA256+"'", "EXPECT_SHA='"+hex.EncodeToString(sum[:])+"'", 1)
				r.cpBody = wrongVersion
				tc.want = fmt.Sprintf("lattice-agent-fetch v1 1:cp:0:%d:1 result:1:verify", len(wrongVersion))
			case "no fetcher":
				r.fetcher = "no-such-fetcher"
			}
			o := runWalkScript(t, s, r)
			if o.exit != tc.exit {
				t.Fatalf("exit %d, want %d, stderr:\n%s", o.exit, tc.exit, o.stderr)
			}
			lines := strings.Split(strings.TrimRight(o.stderr, "\n"), "\n")
			if last := lines[len(lines)-1]; last != tc.want || o.summary != tc.want {
				t.Fatalf("the last stderr line must be the summary %q, got %q (parsed %q), stderr:\n%s", tc.want, last, o.summary, o.stderr)
			}
		})
	}
}

// Only a strictly shaped summary is kept, and only from the node's own
// output; the audit records it for a success and a failure alike.
func TestAgentUpdateTaskResultRecordsTheFetchSummary(t *testing.T) {
	for _, tc := range []struct {
		output string
		want   string
	}{
		{"x\nlattice-agent-fetch v1 1:cp.gz:28:524288:30 2:up:0:13512866:200 result:0:done\n", "lattice-agent-fetch v1 1:cp.gz:28:524288:30 2:up:0:13512866:200 result:0:done"},
		{"lattice-agent-fetch v1 1:cp:18:5:- p2:cp:0:9:3 result:0:done", "lattice-agent-fetch v1 1:cp:18:5:- p2:cp:0:9:3 result:0:done"},
		{"lattice-agent-fetch v1 1:cp:0:1:1 result:0:done\nlattice-agent-fetch v1 result:1:prepare\n", "lattice-agent-fetch v1 result:1:prepare"},
		{"lattice-agent-fetch v1 result:1:prepare; rm -rf /", ""},
		{"lattice-agent-fetch v1 1:cp:0:1:1 result:0:done <script>", ""},
		{"lattice-agent-fetch v1 1:m.evil:0:1:1 result:0:done", ""},
		{"lattice-agent-fetch v1 " + strings.Repeat("1:cp:0:1:1 ", 9) + "result:0:done", ""},
		{"lattice-agent-fetch v2 1:cp:0:1:1 result:0:done", ""},
		{"no summary at all", ""},
	} {
		got, ok := parseAgentFetchSummary(tc.output)
		if got != tc.want || ok != (tc.want != "") {
			t.Fatalf("parse %q = %q %t, want %q", tc.output, got, ok, tc.want)
		}
	}

	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	line := "lattice-agent-fetch v1 1:cp:28:1000:30 2:up:0:9000:12 result:0:done"
	for _, tc := range []struct {
		result model.TaskResult
		action string
	}{
		{model.TaskResult{Stderr: "lattice agent update: something\n" + line + "\n"}, "agent.update.awaiting_confirmation"},
		{model.TaskResult{ExitCode: 28, Stderr: strings.Replace(line, "result:0:done", "result:28:fetch", 1)}, "agent.update.failed"},
	} {
		approval.Status = model.ApprovalApproved
		if err := st.UpsertApproval(approval); err != nil {
			t.Fatal(err)
		}
		if err := srv.handleAgentUpdateTaskResult(httptest.NewRequest("POST", "/api/tasks/results", nil), approval, tc.result); err != nil {
			t.Fatal(err)
		}
		ev, ok := lastAuditFor(st, tc.action)
		if want, _ := parseAgentFetchSummary(tc.result.Stderr); !ok || ev.Metadata["fetch"] != want {
			t.Fatalf("%s must record the fetch summary %q, got %v", tc.action, want, ev.Metadata)
		}
	}
}
