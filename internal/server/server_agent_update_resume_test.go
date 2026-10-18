package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// preResumeApprovals are agent update approvals planned, and their scripts
// rendered, by the code as it stood before resumable downloads: an upstream
// plan, a control-plane plan, and a control-plane plan with a fallback.
type preResumeApproval struct {
	Name   string `json:"name"`
	NodeID string `json:"node_id"`
	Action string `json:"action"`
	Plan   string `json:"plan"`
	Script string `json:"script"`
}

func loadPreResumeApprovals(t *testing.T) []preResumeApproval {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "agent_update_pre_resume_approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []preResumeApproval
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want the three pre-resume approvals, have %d", len(out))
	}
	return out
}

// An operator approves the rendered plan and script. An approval planned
// before resumable downloads existed still renders the script it was approved
// with, byte for byte, and its plan still renders as it was shown.
func TestAgentUpdatePreResumeApprovalsRenderTheScriptTheyWereApprovedWith(t *testing.T) {
	for _, golden := range loadPreResumeApprovals(t) {
		t.Run(golden.Name, func(t *testing.T) {
			approval := model.Approval{NodeID: golden.NodeID, Plugin: agentUpdatePlugin, Action: golden.Action, Plan: golden.Plan}
			payload, err := agentUpdatePayloadFromApproval(approval)
			if err != nil {
				t.Fatal(err)
			}
			if payload.ResumeDownload {
				t.Fatal("a payload planned before resume must decode without it")
			}
			script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
			if err != nil {
				t.Fatal(err)
			}
			if script != golden.Script {
				t.Fatalf("the script changed under an approval planned before resume\n--- approved\n%s\n--- rendered now\n%s", golden.Script, script)
			}
			plan := renderAgentUpdatePlan(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.3.3"}, payload, "manual")
			if plan != golden.Plan {
				t.Fatalf("the plan for a pre-resume payload changed\n--- shown then\n%s\n--- rendered now\n%s", golden.Plan, plan)
			}
		})
	}
}

// Every plan made now resumes, says so in the plan the operator approves,
// and reads the numbers it states from the constants the script uses.
func TestAgentUpdatePlanStatesTheResumableDownload(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if !payload.ResumeDownload {
		t.Fatal("a plan made now must resume")
	}
	for _, want := range []string{
		"\nresume_download: true\n",
		"\n" + agentUpdateResumePlanLine + "\n",
		"as " + agentUpdatePartialPrefix + "<sha256>",
		"inside one " + agentFetchBudgetSec + " s budget",
		"each continuing what the sources before it kept of the same file",
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("plan is missing %q:\n%s", want, approval.Plan)
		}
	}
	script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "CANDIDATE=\"$PARTIAL_DIR/"+agentUpdatePartialPrefix+"$EXPECT_SHA\"\n") {
		t.Fatalf("the kept download must be named by the prefix the plan states:\n%s", script)
	}
	fetches := 0
	for _, line := range strings.Split(script, "\n") {
		// The walk runs wget under fetch_bounded, which adds timeout when the
		// node has one.
		line = strings.TrimPrefix(strings.TrimSpace(line), "fetch_bounded ")
		switch {
		case strings.HasPrefix(line, "curl "):
			fetches++
			if !strings.Contains(line, " -C - -o \"$CANDIDATE\" ") {
				t.Fatalf("every curl fetch must continue the kept file: %s", line)
			}
		case strings.HasPrefix(line, "wget "):
			fetches++
			if !strings.Contains(line, " -c -O \"$CANDIDATE\" ") {
				t.Fatalf("every wget fetch must continue the kept file: %s", line)
			}
		}
	}
	if fetches != 4 {
		t.Fatalf("want the control-plane and fallback fetch for curl and for wget, found %d:\n%s", fetches, script)
	}
	if strings.Contains(script, "mktemp") || strings.Contains(script, "$WORK") {
		t.Fatalf("a resumable download must not land in the per-task temp dir, which is removed on exit:\n%s", script)
	}
	// The kept file is root-only at every step, the verified one included.
	if strings.Contains(script, "chmod 0755 \"$CANDIDATE\"") || !strings.Contains(script, "\nchmod 0700 \"$CANDIDATE\"\nCANDIDATE_VERSION=") {
		t.Fatalf("the verified download beside the install path must stay root-only:\n%s", script)
	}
	// The kept file goes once its copy is installed, and not before.
	install := strings.Index(script, "mv \"$TARGET.new\" \"$TARGET\"\n")
	removed := strings.Index(script, "mv \"$TARGET.new\" \"$TARGET\"\nrm -f \"$CANDIDATE\"\n")
	if install < 0 || removed != install {
		t.Fatalf("the kept download must be removed right after the install:\n%s", script)
	}
}

// The kept file's name comes from the pinned digest, and only a validated
// digest reaches a script: a payload whose sha256 could steer the path does
// not decode, and no script renders for it.
func TestAgentUpdateResumePathCannotBeSteeredByTheDigest(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if !agentSHA256Re.MatchString(payload.SHA256) || !strings.Contains(approval.Plan, "\nsha256: "+payload.SHA256+"\n") {
		t.Fatalf("a decoded digest must be 64 lowercase hex characters, got %q", payload.SHA256)
	}
	for _, sha := range []string{
		"../../../../etc/cron.d/x",
		strings.Repeat("a", 63) + "/",
		strings.Repeat("a", 63) + "*",
		strings.Repeat("a", 32) + " " + strings.Repeat("a", 31),
		"$(touch pwned)" + strings.Repeat("a", 50),
	} {
		bad := payload
		bad.SHA256 = sha
		approval.Action = agentUpdateApprovalAction(bad)
		if _, err := agentUpdatePayloadFromApproval(approval); err == nil {
			t.Fatalf("sha256 %q must not decode", sha)
		}
		if _, err := agentUpdateApplyScript(approval, artifactTestPublicURL); err == nil {
			t.Fatalf("sha256 %q must not render a script", sha)
		}
	}
}

// A control-plane approval planned before resume is pending after a failed
// run, as the four 2026-10-17 nodes were. Approving it again would rerun the
// download that cannot finish, so it is refused as stale with resume_download
// named, and the re-plan resumes.
func TestAgentUpdatePreResumeApprovalIsReplannedBeforeItRunsAgain(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	data, digest := testAgentBinary()
	if _, err := srv.storeAgentArtifact(agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}, data); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.4",
		BinaryURL: fallbackTestReleaseURL, SHA256: digest, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	payload.ResumeDownload = false
	payload.Sources, payload.ChunkManifest = nil, nil
	approval.Action = agentUpdateApprovalAction(payload)
	approval.Plan = strings.Replace(approval.Plan, "resume_download: true\n", "", 1)
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if stale, reason := srv.agentUpdateApprovalLocalStaleness(approval); !stale || !strings.Contains(reason, "resume_download planned=false current=true") {
		t.Fatalf("a pre-resume approval must read as stale with the field named, got stale=%t reason=%q", stale, reason)
	}
	cookies, csrf := loginSession(t, handler)
	res := approveAgentUpdateOverHTTP(t, handler, cookies, csrf, toApprovalView(approval))
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("a pre-resume approval must be re-planned, approve answered %d", res.StatusCode)
	}
	var apiErr model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&apiErr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(apiErr.Error.Message, "changed fields: resume_download planned=false current=true") {
		t.Fatalf("refusal must name the resume change, got %q", apiErr.Error.Message)
	}
	replanned := planAgentUpdateOverHTTP(t, handler, cookies, csrf)
	if !strings.Contains(replanned.Plan, "\nresume_download: true\n") {
		t.Fatalf("the re-plan must resume:\n%s", replanned.Plan)
	}
}

// The same for an official-release policy, whose staleness check does not
// re-resolve the release: a plan without resume is stale there too.
func TestAgentUpdatePreResumeOfficialApprovalIsStale(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	data, digest := testAgentBinary()
	if _, err := srv.storeAgentArtifact(agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}, data); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, TargetVersion: "0.3.4",
		InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if stale, reason := srv.agentUpdateApprovalLocalStaleness(approval); stale {
		t.Fatalf("a plan made now must not be stale: %s", reason)
	}
	old := approvalWithResume(t, approval, false)
	if stale, reason := srv.agentUpdateApprovalLocalStaleness(old); !stale || !strings.Contains(reason, "resume_download planned=false current=true") {
		t.Fatalf("a pre-resume official approval must read as stale with the field named, got stale=%t reason=%q", stale, reason)
	}
}

// resumableScripts renders the resumable download for each shape a plan can
// take: the control plane with and without a fallback, and the upstream
// release alone. walk picks the source walk every plan gets now, or the
// download approvals planned before it still render.
func resumableScripts(t *testing.T, approval model.Approval, walk bool) map[string]struct {
	script  string
	payload agentUpdatePayload
} {
	t.Helper()
	base, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if !walk {
		approval = approvalBeforeTheWalk(approval)
	}
	if strings.Contains(approval.Plan, agentUpdateCutoffPlanLine) != walk {
		t.Fatalf("walk %t but the plan says otherwise:\n%s", walk, approval.Plan)
	}
	out := map[string]struct {
		script  string
		payload agentUpdatePayload
	}{}
	for name, mutate := range map[string]func(p *agentUpdatePayload){
		"control plane with fallback": func(p *agentUpdatePayload) {},
		"control plane":               func(p *agentUpdatePayload) { p.FallbackURL = "" },
		"upstream": func(p *agentUpdatePayload) {
			p.BinarySource, p.BinaryURL, p.FallbackURL = agentBinarySourceUpstream, fallbackTestReleaseURL, ""
		},
	} {
		p := base
		p.ResumeDownload = true
		mutate(&p)
		// Without mirrors a source list renders the walk an approval planned
		// before it renders; the shapes built here take none.
		p.Sources, p.ChunkManifest = nil, nil
		approval.Action = agentUpdateApprovalAction(p)
		script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = struct {
			script  string
			payload agentUpdatePayload
		}{script, p}
	}
	return out
}

// What the resumable download does with a file an earlier attempt kept, for
// every plan shape and both fetchers, under the stub fetchers that continue a
// file the way curl -C - and wget -c do. This is the download approvals
// planned before the source walk render; the walk has its own tests.
func TestAgentUpdateResumableDownloadKeepsAndContinues(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _, _ := seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	half := len(data) / 2
	// corruptHead differs from data before half and matches it after, so a
	// fetch that continues from half produces data and one that starts over
	// does not.
	corruptHead := append(bytes.Repeat([]byte{'#'}, half), data[half:]...)

	for shape, rendered := range resumableScripts(t, approval, false) {
		for _, fetcher := range []string{"curl", "wget"} {
			first := rendered.payload.BinaryURL
			run := func(t *testing.T, r fetchStubRun) fetchStubOutcome {
				t.Helper()
				r.fetcher = fetcher
				r.cpURL, r.fbURL = rendered.payload.BinaryURL, rendered.payload.FallbackURL
				return runAgentUpdateFetch(t, rendered.script, r)
			}
			t.Run(shape+"/"+fetcher+"/a cut download is kept, then continued", func(t *testing.T) {
				o := run(t, fetchStubRun{cpBody: data, cpCut: half, cpExit: 18, fbExit: 18})
				if o.exit == 0 || !o.leftover || !bytes.Equal(o.received, data[:half]) {
					t.Fatalf("the first attempt must fail and keep the %d bytes it got: exit %d kept %d bytes, stderr:\n%s", half, o.exit, len(o.received), o.stderr)
				}
				o = run(t, fetchStubRun{kept: o.received, cpBody: corruptHead})
				if o.exit != 0 || !bytes.Equal(o.received, data) {
					t.Fatalf("the next attempt must continue from byte %d: exit %d, stderr:\n%s", half, o.exit, o.stderr)
				}
				if !strings.Contains(o.stdout, "continuing the download an earlier attempt kept in "+o.candidate) {
					t.Fatalf("the task output must say it is continuing, stdout:\n%s", o.stdout)
				}
				if len(o.calls) != 1 || !strings.HasSuffix(o.calls[0], first) {
					t.Fatalf("a kept download continues from the first source: %q", o.calls)
				}
			})
			t.Run(shape+"/"+fetcher+"/a kept file of other bytes is deleted", func(t *testing.T) {
				o := run(t, fetchStubRun{kept: bytes.Repeat([]byte{'#'}, half), cpBody: data})
				if o.exit == 0 || o.leftover || !strings.Contains(o.stderr, "sha256 mismatch expected="+rendered.payload.SHA256) ||
					!strings.Contains(o.stderr, "deleted the download so the next attempt starts over") {
					t.Fatalf("a spliced file must fail the digest and be deleted: exit %d leftover %t, stderr:\n%s", o.exit, o.leftover, o.stderr)
				}
				o = run(t, fetchStubRun{cpBody: data})
				if o.exit != 0 || !bytes.Equal(o.received, data) {
					t.Fatalf("after the delete a fresh download must succeed: exit %d, stderr:\n%s", o.exit, o.stderr)
				}
			})
			t.Run(shape+"/"+fetcher+"/a complete kept file is used as it is", func(t *testing.T) {
				o := run(t, fetchStubRun{kept: data, cpBody: corruptHead})
				if o.exit != 0 || !bytes.Equal(o.received, data) {
					t.Fatalf("exit %d, stderr:\n%s", o.exit, o.stderr)
				}
			})
			t.Run(shape+"/"+fetcher+"/other digests go, a planted symlink is not followed", func(t *testing.T) {
				other := agentUpdatePartialPrefix + strings.Repeat("a", 64)
				var victim string
				o := run(t, fetchStubRun{cpBody: data, prepare: func(installDir, candidate string) {
					if err := os.WriteFile(filepath.Join(installDir, other), []byte("old download"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(installDir, "lattice-agent"), []byte("installed agent"), 0o755); err != nil {
						t.Fatal(err)
					}
					victim = filepath.Join(filepath.Dir(installDir), "victim")
					if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(victim, candidate); err != nil {
						t.Fatal(err)
					}
				}})
				if o.exit != 0 || !bytes.Equal(o.received, data) {
					t.Fatalf("exit %d, stderr:\n%s", o.exit, o.stderr)
				}
				if got, _ := os.ReadFile(victim); string(got) != "precious" {
					t.Fatalf("the download wrote through a symlink at the kept path: victim now %q", got)
				}
				if info, err := os.Lstat(o.candidate); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatalf("the kept path must be a fresh 0600 regular file, got %v %v", info.Mode(), err)
				}
				if _, err := os.Stat(filepath.Join(o.installDir, other)); !os.IsNotExist(err) {
					t.Fatalf("a download kept for another digest must be removed: %v", err)
				}
				if got, _ := os.ReadFile(filepath.Join(o.installDir, "lattice-agent")); string(got) != "installed agent" {
					t.Fatal("cleaning kept downloads must not touch anything else in the install directory")
				}
			})
		}
		// curl answers 33 when a server ignores the range. That partial can
		// never be continued from there, so it goes and the next fetch, the
		// fallback or the next attempt, starts over.
		t.Run(shape+"/curl/a server that ignores ranges", func(t *testing.T) {
			r := fetchStubRun{fetcher: "curl", cpURL: rendered.payload.BinaryURL, fbURL: rendered.payload.FallbackURL,
				kept: bytes.Repeat([]byte{'#'}, 10), cpBody: data, cpCut: 5, cpExit: 33, fbBody: data}
			o := runAgentUpdateFetch(t, rendered.script, r)
			if rendered.payload.FallbackURL == "" {
				if o.exit != 33 || o.leftover {
					t.Fatalf("the unresumable partial must be removed and the attempt fail: exit %d leftover %t, stderr:\n%s", o.exit, o.leftover, o.stderr)
				}
				return
			}
			if o.exit != 0 || !bytes.Equal(o.received, data) {
				t.Fatalf("the fallback must start over after a 33: exit %d, stderr:\n%s", o.exit, o.stderr)
			}
		})
	}
	// The fallback continues what the control plane sent instead of starting
	// over: its first half differs, so only a continuation verifies.
	t.Run("the fallback continues a control-plane partial", func(t *testing.T) {
		rendered := resumableScripts(t, approval, false)["control plane with fallback"]
		for _, fetcher := range []string{"curl", "wget"} {
			o := runAgentUpdateFetch(t, rendered.script, fetchStubRun{fetcher: fetcher,
				cpURL: rendered.payload.BinaryURL, fbURL: rendered.payload.FallbackURL,
				cpBody: data, cpCut: half, cpExit: 28, fbBody: corruptHead})
			if o.exit != 0 || !bytes.Equal(o.received, data) {
				t.Fatalf("%s: exit %d, stderr:\n%s", fetcher, o.exit, o.stderr)
			}
			if len(o.calls) != 2 || strings.Contains(o.calls[1], "X-Lattice-Task") {
				t.Fatalf("%s: the continuing fallback must still carry no lease: %q", fetcher, o.calls)
			}
		}
	})
}

// cutAfterWriter sends the first left bytes of a response body and then drops
// the connection, the way a slow uplink's download ends when its budget runs
// out.
type cutAfterWriter struct {
	http.ResponseWriter
	left int
}

func (w *cutAfterWriter) Write(p []byte) (int, error) {
	if len(p) <= w.left {
		w.left -= len(p)
		return w.ResponseWriter.Write(p)
	}
	n, _ := w.ResponseWriter.Write(p[:w.left])
	w.left -= n
	w.ResponseWriter.(http.Flusher).Flush()
	panic(http.ErrAbortHandler)
}

// The resumable download end to end: the rendered fetch, run by the host's own
// curl and wget, against the real binary handler over TLS. The control plane
// drops the first attempt mid-body; the next attempt sends the lease and a
// range for the rest, and the digest check passes. With a fallback, the
// release URL continues the control-plane partial, without the lease. This is
// the download approvals planned before the source walk render; the walk
// against the real handler is in server_agent_update_walk_test.go.
func TestAgentUpdateResumableDownloadAgainstTheRealHandler(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, ref, task := seedControlPlaneUpdate(t, srv, st)
	planned, _ := controlPlaneApprovalFor(st, "node-a")
	scripts := resumableScripts(t, planned, false)

	var mu sync.Mutex
	var cpSeen, fbSeen []http.Header
	cutAfter, ignoreRange := 0, false
	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cpSeen = append(cpSeen, r.Header.Clone())
		cut, strip := cutAfter, ignoreRange
		mu.Unlock()
		if strip {
			r.Header.Del("Range")
		}
		if cut > 0 {
			w = &cutAfterWriter{ResponseWriter: w, left: cut}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(cp.Close)
	fb := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fbSeen = append(fbSeen, r.Header.Clone())
		mu.Unlock()
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(fb.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	attemptWith := func(t *testing.T, script, fetcher string, cut int, strip bool, kept []byte) fetchStubOutcome {
		t.Helper()
		mu.Lock()
		cpSeen, fbSeen, cutAfter, ignoreRange = nil, nil, cut, strip
		mu.Unlock()
		return runAgentUpdateFetch(t, script, fetchStubRun{
			fetcher: fetcher, real: true, caFile: caFile, date: "host", kept: kept,
			cpURL: cp.URL + ref.urlPath(), fbURL: fb.URL + "/lattice-agent-linux-amd64",
			env: []string{"LATTICE_TASK_ID=" + task.ID, "LATTICE_TASK_LEASE_ID=" + task.LeaseID},
		})
	}
	attempt := func(t *testing.T, script, fetcher string, cut int, kept []byte) fetchStubOutcome {
		t.Helper()
		return attemptWith(t, script, fetcher, cut, false, kept)
	}
	leased := func(h http.Header) bool {
		return h.Get(agentTaskIDHeader) == task.ID && h.Get(agentTaskLeaseHeader) == task.LeaseID
	}
	cut := len(data) / 3

	for _, fetcher := range []string{"curl", "wget"} {
		t.Run(fetcher+"/cut, then resumed by the next attempt", func(t *testing.T) {
			script := scripts["control plane"].script
			first := attempt(t, script, fetcher, cut, nil)
			if first.exit == 0 || !first.leftover || len(first.received) == 0 || len(first.received) >= len(data) ||
				!bytes.Equal(first.received, data[:len(first.received)]) {
				t.Fatalf("the cut attempt must fail and keep a prefix of the binary: exit %d kept %d of %d bytes, stderr:\n%s",
					first.exit, len(first.received), len(data), first.stderr)
			}
			if info, err := os.Stat(first.candidate); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("the kept download must be 0600: %v %v", info.Mode(), err)
			}
			second := attempt(t, script, fetcher, 0, first.received)
			if second.exit != 0 || !bytes.Equal(second.received, data) {
				t.Fatalf("the next attempt must finish the download: exit %d, %d bytes, stderr:\n%s", second.exit, len(second.received), second.stderr)
			}
			mu.Lock()
			seen := append([]http.Header(nil), cpSeen...)
			mu.Unlock()
			if len(seen) != 1 || !leased(seen[0]) || seen[0].Get("Range") != fmt.Sprintf("bytes=%d-", len(first.received)) {
				t.Fatalf("the next attempt must ask the control plane, with the lease, for the rest: %v", seen)
			}
			if _, ok := servedRangeAudit(st, fmt.Sprintf("bytes=%d-", len(first.received))); !ok {
				t.Fatalf("the audit must record the range served, bytes=%d-", len(first.received))
			}
		})
		t.Run(fetcher+"/the fallback continues a control-plane partial", func(t *testing.T) {
			o := attempt(t, scripts["control plane with fallback"].script, fetcher, cut, nil)
			if o.exit != 0 || !bytes.Equal(o.received, data) {
				t.Fatalf("exit %d, %d bytes, stderr:\n%s", o.exit, len(o.received), o.stderr)
			}
			mu.Lock()
			cps, fbs := append([]http.Header(nil), cpSeen...), append([]http.Header(nil), fbSeen...)
			mu.Unlock()
			if len(cps) == 0 || !leased(cps[0]) {
				t.Fatalf("the control-plane fetch must carry the lease: %v", cps)
			}
			if len(fbs) != 1 || fbs[0].Get(agentTaskIDHeader) != "" || fbs[0].Get(agentTaskLeaseHeader) != "" {
				t.Fatalf("the fallback must be one fetch without the lease: %v", fbs)
			}
			if !strings.HasPrefix(fbs[0].Get("Range"), "bytes=") || fbs[0].Get("Range") == "bytes=0-" {
				t.Fatalf("the fallback must continue the control-plane partial, asked for %q", fbs[0].Get("Range"))
			}
		})
		t.Run(fetcher+"/a kept file of other bytes is deleted, then fetched fresh", func(t *testing.T) {
			script := scripts["control plane"].script
			o := attempt(t, script, fetcher, 0, bytes.Repeat([]byte{'#'}, cut))
			if o.exit == 0 || o.leftover || !strings.Contains(o.stderr, "sha256 mismatch") {
				t.Fatalf("a spliced file must fail the digest and be deleted: exit %d leftover %t, stderr:\n%s", o.exit, o.leftover, o.stderr)
			}
			o = attempt(t, script, fetcher, 0, nil)
			if o.exit != 0 || !bytes.Equal(o.received, data) {
				t.Fatalf("exit %d, stderr:\n%s", o.exit, o.stderr)
			}
		})
		// A hop in front of the control plane that strips Range answers a
		// resume with the whole object. That must never wedge a node: wget -c
		// starts the file over within the attempt, and curl refuses (33), so
		// the script drops the partial and the next attempt starts over, as
		// every attempt did before resume.
		t.Run(fetcher+"/a hop that ignores ranges", func(t *testing.T) {
			script := scripts["control plane"].script
			o := attemptWith(t, script, fetcher, 0, true, data[:cut])
			mu.Lock()
			seen := append([]http.Header(nil), cpSeen...)
			mu.Unlock()
			if len(seen) == 0 || seen[0].Get("Range") != fmt.Sprintf("bytes=%d-", cut) {
				t.Fatalf("the attempt must have asked to resume: %v", seen)
			}
			if fetcher == "wget" {
				if o.exit != 0 || !bytes.Equal(o.received, data) {
					t.Fatalf("wget must start over within the attempt: exit %d, %d bytes, stderr:\n%s", o.exit, len(o.received), o.stderr)
				}
				return
			}
			if o.exit != 33 || o.leftover {
				t.Fatalf("curl must refuse and the partial must go: exit %d leftover %t, stderr:\n%s", o.exit, o.leftover, o.stderr)
			}
			o = attemptWith(t, script, fetcher, 0, true, nil)
			if o.exit != 0 || !bytes.Equal(o.received, data) {
				t.Fatalf("the next attempt must start over and finish: exit %d, stderr:\n%s", o.exit, o.stderr)
			}
		})
	}
}
