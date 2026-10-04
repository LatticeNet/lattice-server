package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const fallbackTestReleaseURL = "https://downloads.example.com/lattice-agent-linux-amd64"

// A control-plane plan names the upstream URL for the same pinned bytes, in the
// payload the approval binds and in the plan text whose hash the operator
// approves. 2026-10-04: a node whose agent reaches the control plane through a
// relay could not download from it inside the task, and had no other path.
func TestAgentUpdateControlPlanePlanNamesThePinnedURLAsFallback(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, ok := controlPlaneApprovalFor(st, "node-a")
	if !ok {
		t.Fatal("expected an agent update approval for node-a")
	}
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if payload.FallbackURL != fallbackTestReleaseURL {
		t.Fatalf("fallback_url = %q, want the policy's pinned URL %q", payload.FallbackURL, fallbackTestReleaseURL)
	}
	if !strings.Contains(approval.Plan, "\nfallback_url: "+fallbackTestReleaseURL+"\n") {
		t.Fatalf("the plan an operator approves must show the fallback URL:\n%s", approval.Plan)
	}
	if !strings.Contains(approval.Plan, "if the control-plane download fails, the node fetches fallback_url once, without the task lease") {
		t.Fatalf("the plan must say when the fallback is used and that it carries no lease:\n%s", approval.Plan)
	}
}

// The official-release path needs no SHA256SUMS fetch to name its fallback: the
// release URL is deterministic and the stored digest is the pin either way.
func TestAgentUpdateOfficialControlPlanePlanFallsBackToTheReleaseAsset(t *testing.T) {
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
		t.Fatalf("plan from the stored artifact: %v", err)
	}
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/" + defaultAgentReleaseRepo + "/releases/download/v0.3.4/lattice-agent-linux-amd64"
	if payload.BinarySource != agentBinarySourceControlPlane || payload.FallbackURL != want || payload.SHA256 != digest {
		t.Fatalf("payload source=%q fallback=%q sha=%q, want control-plane, %q, the stored digest",
			payload.BinarySource, payload.FallbackURL, payload.SHA256, want)
	}
	if !strings.Contains(approval.Plan, "\nfallback_url: "+want+"\n") {
		t.Fatalf("plan does not show the release URL fallback:\n%s", approval.Plan)
	}
}

// An upstream plan already downloads from the release; it has nothing to fall
// back to, and its plan and script stay as they were.
func TestAgentUpdateUpstreamPlanHasNoFallback(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	approval := seedAgentUpdateApproved(t, srv, st)
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if payload.BinarySource != agentBinarySourceUpstream || payload.FallbackURL != "" {
		t.Fatalf("upstream plan got source=%q fallback=%q", payload.BinarySource, payload.FallbackURL)
	}
	if strings.Contains(approval.Plan, "fallback_url") {
		t.Fatalf("an upstream plan must not mention a fallback:\n%s", approval.Plan)
	}
	script, err := agentUpdateApplyScript(approval, srv.publicURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"FALLBACK_URL", "FETCH_START", "falling back"} {
		if strings.Contains(script, absent) {
			t.Fatalf("an upstream script got %q:\n%s", absent, script)
		}
	}
}

// The fallback URL is part of what the operator approved. If the policy would
// now name a different one, the plan is stale like any other bound field, and
// the refusal says which field moved. A re-plan carries the new URL and
// approves normally.
func TestAgentUpdateApproveRefusesAChangedFallbackURL(t *testing.T) {
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
	cookies, csrf := loginSession(t, handler)
	planned := planAgentUpdateOverHTTP(t, handler, cookies, csrf)

	const mirror = "https://mirror.example.com/lattice-agent-linux-amd64"
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.4",
		BinaryURL: mirror, SHA256: digest, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approve := approveAgentUpdateOverHTTP(t, handler, cookies, csrf, planned)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusConflict {
		t.Fatalf("a plan whose fallback moved must be re-planned, approve answered %d", approve.StatusCode)
	}
	var apiErr model.APIErrorResponse
	if err := json.NewDecoder(approve.Body).Decode(&apiErr); err != nil {
		t.Fatal(err)
	}
	want := "changed fields: fallback_url planned=" + fallbackTestReleaseURL + " current=" + mirror + ";"
	if apiErr.Error.Code != model.APIErrorApprovalStale || !strings.Contains(apiErr.Error.Message, want) {
		t.Fatalf("refusal must name the fallback and only the fallback, got code=%q message=%q", apiErr.Error.Code, apiErr.Error.Message)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("a refused approval must not queue a task, have %d tasks", len(st.Tasks()))
	}

	replanned := planAgentUpdateOverHTTP(t, handler, cookies, csrf)
	if !strings.Contains(replanned.Plan, "\nfallback_url: "+mirror+"\n") {
		t.Fatalf("re-plan must carry the new fallback:\n%s", replanned.Plan)
	}
	ok := approveAgentUpdateOverHTTP(t, handler, cookies, csrf, replanned)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("an up-to-date control-plane plan with a fallback must approve, got %d", ok.StatusCode)
	}
}

// A control-plane approval planned before fallbacks existed is pending (an
// execution failure returns it there). Approving it again would run the same
// download that failed, so it is refused as stale with fallback_url named, and
// the re-plan is what carries the fallback.
func TestAgentUpdatePreFallbackApprovalIsReplannedBeforeItRunsAgain(t *testing.T) {
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
	payload.FallbackURL = ""
	approval.Action = agentUpdateApprovalAction(payload)
	approval.Plan = strings.Replace(approval.Plan, "fallback_url: "+fallbackTestReleaseURL+"\n", "", 1)
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	res := approveAgentUpdateOverHTTP(t, handler, cookies, csrf, toApprovalView(approval))
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("a pre-fallback control-plane approval must be re-planned, approve answered %d", res.StatusCode)
	}
	var apiErr model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&apiErr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(apiErr.Error.Message, "changed fields: fallback_url planned= current="+fallbackTestReleaseURL+";") {
		t.Fatalf("refusal must name the missing fallback, got %q", apiErr.Error.Message)
	}
	replanned := planAgentUpdateOverHTTP(t, handler, cookies, csrf)
	if !strings.Contains(replanned.Plan, "\nfallback_url: "+fallbackTestReleaseURL+"\n") {
		t.Fatalf("the re-plan must carry the fallback:\n%s", replanned.Plan)
	}
}

func planAgentUpdateOverHTTP(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) approvalView {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("plan answered %d", res.StatusCode)
	}
	var view approvalView
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	return view
}

func approveAgentUpdateOverHTTP(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, view approvalView) *http.Response {
	t.Helper()
	return doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": view.ID, "queue_apply": true, "plan_sha256": planSHA256(view.Plan)})),
		cookies, csrf)
}

// A control-plane approval planned before fallbacks existed carries no
// fallback_url and renders the download it was approved with, byte for byte.
func TestAgentUpdateControlPlaneApprovalWithoutFallbackKeepsItsDownload(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	payload.FallbackURL = ""
	approval.Action = agentUpdateApprovalAction(payload)
	if strings.Contains(approval.Action, "fallback") {
		t.Fatal("an empty fallback must not appear in the encoded payload")
	}
	script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	const download = "CANDIDATE=\"$WORK/lattice-agent\"\n" +
		"if command -v curl >/dev/null 2>&1; then\n" +
		"  curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 480 -H \"X-Lattice-Task-Id: $LATTICE_TASK_ID\" -H \"X-Lattice-Task-Lease: $LATTICE_TASK_LEASE_ID\" -o \"$CANDIDATE\" \"$URL\"\n" +
		"elif command -v wget >/dev/null 2>&1; then\n" +
		"  wget --https-only -q --max-redirect=0 --timeout=20 --tries=2 --header=\"X-Lattice-Task-Id: $LATTICE_TASK_ID\" --header=\"X-Lattice-Task-Lease: $LATTICE_TASK_LEASE_ID\" -O \"$CANDIDATE\" \"$URL\"\n" +
		"else\n" +
		"  echo 'lattice agent update: curl or wget is required' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if command -v sha256sum >/dev/null 2>&1; then\n"
	if !strings.Contains(script, download) {
		t.Fatalf("a pre-fallback control-plane approval must keep its exact download:\n%s", script)
	}
	for _, absent := range []string{"FALLBACK_URL", "FETCH_START", "falling back"} {
		if strings.Contains(script, absent) {
			t.Fatalf("a pre-fallback approval got %q:\n%s", absent, script)
		}
	}
}

// The fallback is only meaningful behind a control-plane source and must meet
// the same URL rules as binary_url, since the script fetches it as root.
func TestAgentUpdatePayloadValidatesTheFallbackURL(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(p *agentUpdatePayload){
		"upstream source": func(p *agentUpdatePayload) {
			p.BinarySource = agentBinarySourceUpstream
			p.BinaryURL = fallbackTestReleaseURL
		},
		"plain http":   func(p *agentUpdatePayload) { p.FallbackURL = "http://downloads.example.com/lattice-agent" },
		"query string": func(p *agentUpdatePayload) { p.FallbackURL = fallbackTestReleaseURL + "?token=x" },
	} {
		bad := payload
		mutate(&bad)
		approval.Action = agentUpdateApprovalAction(bad)
		if _, err := agentUpdatePayloadFromApproval(approval); err == nil {
			t.Fatalf("%s: a payload with fallback %q and source %q must not decode", name, bad.FallbackURL, bad.BinarySource)
		}
		if _, err := agentUpdateApplyScript(approval, artifactTestPublicURL); err == nil {
			t.Fatalf("%s: must not render a script", name)
		}
	}
}

// fetchStubRun describes one run of the rendered download under sh with stub
// fetchers. cpURL and fbURL are the URLs the stub answers for; anything else
// exits 97.
type fetchStubRun struct {
	fetcher        string
	cpURL, fbURL   string
	cpExit, fbExit int
	cpBody, fbBody []byte
	elapsed        int
	// date is "" for a stub that reports 1000 then 1000+elapsed, "absent" for
	// none on PATH, and "no-epoch" for one that prints %s literally, as a date
	// without %s support does.
	date string
}

type fetchStubOutcome struct {
	exit     int
	stderr   string
	calls    []string
	received []byte
	leftover bool
	dir      string
}

// runAgentUpdateFetch runs the download and digest check cut from a rendered
// script under sh. PATH holds only the stubs and the tools the fragment uses,
// so the host's real curl, wget and date can never answer instead. touch is
// there too, so that a URL which escaped its quoting and ran a command would
// leave a file behind. The working directory is the run's own temp dir.
func runAgentUpdateFetch(t *testing.T, script string, r fetchStubRun) fetchStubOutcome {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	work := filepath.Join(dir, "work")
	for _, d := range []string{bin, work} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"cat", "rm", "awk", "sha256sum", "shasum", "touch"} {
		if path, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	fetchStub := "#!/bin/sh\n" +
		"out=''; prev=''; last=''\n" +
		"for a in \"$@\"; do if [ \"$prev\" = -o ] || [ \"$prev\" = -O ]; then out=$a; fi; prev=$a; last=$a; done\n" +
		"printf '%s\\n' \"$*\" >>\"$STUB_CALLS\"\n" +
		"case \"$last\" in\n" +
		"  \"$STUB_CP_URL\") if [ -r \"$STUB_CP_BODY\" ]; then cat \"$STUB_CP_BODY\" >\"$out\"; else printf partial >\"$out\"; fi; code=$STUB_CP_EXIT ;;\n" +
		"  \"$STUB_FB_URL\") [ -r \"$STUB_FB_BODY\" ] && cat \"$STUB_FB_BODY\" >\"$out\"; code=$STUB_FB_EXIT ;;\n" +
		"  *) echo \"stub: unexpected url $last\" >&2; exit 97 ;;\n" +
		"esac\n" +
		"if [ \"$code\" != 0 ]; then echo \"stub: ($code) Connection timed out after 20002 milliseconds\" >&2; fi\n" +
		"exit \"$code\"\n"
	stubs := map[string]string{r.fetcher: fetchStub}
	switch r.date {
	case "":
		stubs["date"] = "#!/bin/sh\n" +
			"if [ -e \"$STUB_DATE_STATE\" ]; then echo $((1000 + STUB_ELAPSED)); else : >\"$STUB_DATE_STATE\"; echo 1000; fi\n"
	case "no-epoch":
		stubs["date"] = "#!/bin/sh\necho '%s'\n"
	case "absent":
	default:
		t.Fatalf("unknown date mode %q", r.date)
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cpPath := filepath.Join(dir, "control-plane-body")
	fbPath := filepath.Join(dir, "fallback-body")
	for path, body := range map[string][]byte{cpPath: r.cpBody, fbPath: r.fbBody} {
		if body == nil {
			continue
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	calls := filepath.Join(dir, "calls")
	cmd := exec.Command("sh", "-c", agentUpdateFetchFragment(t, script, work))
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + bin,
		"LATTICE_TASK_ID=task-1",
		"LATTICE_TASK_LEASE_ID=lease-1",
		"STUB_CALLS=" + calls,
		"STUB_CP_URL=" + r.cpURL,
		"STUB_FB_URL=" + r.fbURL,
		"STUB_CP_EXIT=" + strconv.Itoa(r.cpExit),
		"STUB_FB_EXIT=" + strconv.Itoa(r.fbExit),
		"STUB_CP_BODY=" + cpPath,
		"STUB_FB_BODY=" + fbPath,
		"STUB_DATE_STATE=" + filepath.Join(dir, "date-state"),
		"STUB_ELAPSED=" + strconv.Itoa(r.elapsed),
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := fetchStubOutcome{stderr: stderr.String(), dir: dir}
	if exitErr, ok := err.(*exec.ExitError); ok {
		out.exit = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(calls); err == nil {
		out.calls = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	out.received, err = os.ReadFile(filepath.Join(work, "lattice-agent"))
	out.leftover = err == nil
	return out
}

// Runs the download and digest check exactly as rendered for a control-plane
// plan with a fallback, under sh, with curl, wget and date replaced by stubs
// that log their arguments and answer per URL. This is the part of the script
// the fallback changes; the rest needs systemd and is covered elsewhere.
func TestAgentUpdateFallbackDownloadRunsInSh(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _, _ := seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, r fetchStubRun) fetchStubOutcome {
		t.Helper()
		r.cpURL, r.fbURL = payload.BinaryURL, payload.FallbackURL
		return runAgentUpdateFetch(t, script, r)
	}
	leaseOnlyOnFirst := func(t *testing.T, o fetchStubOutcome) {
		t.Helper()
		if len(o.calls) != 2 {
			t.Fatalf("want the control-plane attempt then the fallback, got calls %q", o.calls)
		}
		if !strings.HasSuffix(o.calls[0], payload.BinaryURL) || !strings.Contains(o.calls[0], agentTaskLeaseHeader+": lease-1") {
			t.Fatalf("first call must be the credentialed control-plane fetch: %q", o.calls[0])
		}
		if !strings.HasSuffix(o.calls[1], payload.FallbackURL) || strings.Contains(o.calls[1], "lease-1") || strings.Contains(o.calls[1], "X-Lattice-Task") {
			t.Fatalf("the fallback must carry no task credential: %q", o.calls[1])
		}
	}

	for _, fetcher := range []string{"curl", "wget"} {
		t.Run(fetcher+"/control plane fails, fallback verified", func(t *testing.T) {
			o := run(t, fetchStubRun{fetcher: fetcher, cpExit: 28, fbBody: data})
			if o.exit != 0 || string(o.received) != string(data) {
				t.Fatalf("exit %d, received %d bytes, stderr:\n%s", o.exit, len(o.received), o.stderr)
			}
			leaseOnlyOnFirst(t, o)
			if !strings.Contains(o.stderr, "control-plane download failed; falling back to the release URL "+payload.FallbackURL) {
				t.Fatalf("the fallback must be announced, stderr:\n%s", o.stderr)
			}
			if fetcher == "curl" {
				// Redirects are followed, but only to HTTPS, over TLS 1.2 or
				// newer, within the budget the first attempt left.
				for _, want := range []string{"-fsSL ", "--proto =https ", "--proto-redir =https ", "--tlsv1.2 ", "--max-time 480 "} {
					if !strings.Contains(o.calls[1], want) {
						t.Fatalf("curl fallback is missing %q: %q", want, o.calls[1])
					}
				}
			}
			if fetcher == "wget" && (strings.Contains(o.calls[1], "--max-redirect=0") || !strings.Contains(o.calls[1], "--https-only ")) {
				t.Fatalf("wget fallback must follow release redirects over HTTPS only: %q", o.calls[1])
			}
		})
		t.Run(fetcher+"/fallback bytes fail the digest", func(t *testing.T) {
			o := run(t, fetchStubRun{fetcher: fetcher, cpExit: 28, fbBody: []byte("not the pinned binary")})
			if o.exit == 0 || !strings.Contains(o.stderr, "sha256 mismatch expected="+payload.SHA256) {
				t.Fatalf("a fallback download must be held to the pinned digest: exit %d stderr:\n%s", o.exit, o.stderr)
			}
			leaseOnlyOnFirst(t, o)
		})
		t.Run(fetcher+"/fallback fails too", func(t *testing.T) {
			o := run(t, fetchStubRun{fetcher: fetcher, cpExit: 28, fbExit: 22})
			if o.exit != 22 {
				t.Fatalf("a failed fallback must fail the task with its own status, got %d stderr:\n%s", o.exit, o.stderr)
			}
			leaseOnlyOnFirst(t, o)
			// The control-plane stub left a partial file and the fallback
			// wrote nothing, so a file here is the partial one.
			if o.leftover {
				t.Fatal("the partial control-plane download must be removed before the fallback")
			}
		})
		t.Run(fetcher+"/control plane succeeds", func(t *testing.T) {
			o := run(t, fetchStubRun{fetcher: fetcher, cpBody: data, fbBody: data})
			if o.exit != 0 || string(o.received) != string(data) {
				t.Fatalf("exit %d, received %d bytes, stderr:\n%s", o.exit, len(o.received), o.stderr)
			}
			if len(o.calls) != 1 || strings.Contains(o.stderr, "falling back") {
				t.Fatalf("a successful control-plane fetch must not try the fallback: calls %q stderr:\n%s", o.calls, o.stderr)
			}
		})
		t.Run(fetcher+"/control plane bytes still verified", func(t *testing.T) {
			o := run(t, fetchStubRun{fetcher: fetcher, cpBody: []byte("not the pinned binary"), fbBody: data})
			if o.exit == 0 || !strings.Contains(o.stderr, "sha256 mismatch") || len(o.calls) != 1 {
				t.Fatalf("control-plane bytes must be verified as before: exit %d calls %q stderr:\n%s", o.exit, o.calls, o.stderr)
			}
		})
		// The clock only sizes the curl fallback. Without a usable one the
		// download still runs, and a failure still falls back.
		for _, date := range []string{"absent", "no-epoch"} {
			t.Run(fetcher+"/date "+date+", control plane succeeds", func(t *testing.T) {
				o := run(t, fetchStubRun{fetcher: fetcher, cpBody: data, date: date})
				if o.exit != 0 || string(o.received) != string(data) || len(o.calls) != 1 {
					t.Fatalf("a download must not depend on date: exit %d calls %q stderr:\n%s", o.exit, o.calls, o.stderr)
				}
			})
			t.Run(fetcher+"/date "+date+", control plane fails", func(t *testing.T) {
				o := run(t, fetchStubRun{fetcher: fetcher, cpExit: 28, fbBody: data, date: date})
				if o.exit != 0 || string(o.received) != string(data) {
					t.Fatalf("exit %d, received %d bytes, stderr:\n%s", o.exit, len(o.received), o.stderr)
				}
				leaseOnlyOnFirst(t, o)
				if fetcher == "curl" && !strings.Contains(o.calls[1], "--max-time 460 ") {
					t.Fatalf("without a clock the fallback gets the budget less one connect timeout: %q", o.calls[1])
				}
			})
		}
	}
	t.Run("curl/budget spent", func(t *testing.T) {
		o := run(t, fetchStubRun{fetcher: "curl", cpExit: 28, fbBody: data, elapsed: 470})
		if o.exit != 1 || len(o.calls) != 1 {
			t.Fatalf("with 10 s of the budget left the fallback must not start: exit %d calls %q stderr:\n%s", o.exit, o.calls, o.stderr)
		}
		if !strings.Contains(o.stderr, "control-plane download failed with 10s of the 480 s download budget left; not falling back") {
			t.Fatalf("the skipped fallback must be explained, stderr:\n%s", o.stderr)
		}
		if o.leftover {
			t.Fatal("the partial control-plane download must be removed")
		}
	})
	t.Run("curl/fallback gets the remaining budget", func(t *testing.T) {
		o := run(t, fetchStubRun{fetcher: "curl", cpExit: 28, fbBody: data, elapsed: 20})
		if o.exit != 0 || len(o.calls) != 2 || !strings.Contains(o.calls[1], "--max-time 460 ") {
			t.Fatalf("after a 20 s connect timeout the fallback gets 460 s: exit %d calls %q stderr:\n%s", o.exit, o.calls, o.stderr)
		}
	})
	t.Run("curl/clock stepped back", func(t *testing.T) {
		o := run(t, fetchStubRun{fetcher: "curl", cpExit: 28, fbBody: data, elapsed: -300})
		if o.exit != 0 || len(o.calls) != 2 || !strings.Contains(o.calls[1], "--max-time 460 ") {
			t.Fatalf("a clock that went backwards must not stretch the fallback past the budget: exit %d calls %q stderr:\n%s", o.exit, o.calls, o.stderr)
		}
	})
}

// The URLs reach the script as shell assignments, so their quoting is what
// keeps a URL from running as a command on the node, as root. Normalization
// keeps $(...) and single quotes when every other character in the path is a
// legal URL character, and percent-encodes the whole path, $( included, once
// one character needs it; a backtick always does. Each case is decoded
// through the approval the way a node's script is, rendered, and run.
func TestAgentUpdateScriptQuotesURLsThatCarryShellSyntax(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _, _ := seedControlPlaneUpdate(t, srv, st)
	approval, _ := controlPlaneApprovalFor(st, "node-a")
	base, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, fallback string
		survives       string
	}{
		{"command substitution and quote", "https://downloads.example.com/$(touch$IFS'pwned-fb')/it's", "$(touch$IFS'pwned-fb')/it's"},
		{"backtick", "https://downloads.example.com/`touch$IFS'pwned-tick'`", "%60touch$IFS%27pwned-tick%27%60"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := base
			payload.BinaryURL += "/$(touch$IFS'pwned-cp')/it's"
			payload.FallbackURL = tc.fallback
			approval.Action = agentUpdateApprovalAction(payload)
			decoded, err := agentUpdatePayloadFromApproval(approval)
			if err != nil {
				t.Fatalf("the URLs must survive validation for this test to mean anything: %v", err)
			}
			if !strings.HasSuffix(decoded.BinaryURL, "/$(touch$IFS'pwned-cp')/it's") || !strings.Contains(decoded.FallbackURL, tc.survives) {
				t.Fatalf("normalization changed what this test relies on: binary_url %q fallback_url %q", decoded.BinaryURL, decoded.FallbackURL)
			}
			script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\nURL=" + shellQuote(decoded.BinaryURL) + "\n",
				"\nFALLBACK_URL=" + shellQuote(decoded.FallbackURL) + "\n",
			} {
				if !strings.Contains(script, want) {
					t.Fatalf("script must assign %q single-quoted:\n%s", strings.TrimSpace(want), script)
				}
			}
			for _, fetcher := range []string{"curl", "wget"} {
				o := runAgentUpdateFetch(t, script, fetchStubRun{
					fetcher: fetcher, cpURL: decoded.BinaryURL, fbURL: decoded.FallbackURL, cpExit: 28, fbBody: data,
				})
				for _, name := range []string{"pwned-cp", "pwned-fb", "pwned-tick"} {
					if _, err := os.Stat(filepath.Join(o.dir, name)); err == nil {
						t.Fatalf("%s: a URL ran a command on the node and created %s", fetcher, name)
					}
				}
				if o.exit != 0 || string(o.received) != string(data) {
					t.Fatalf("%s: exit %d, received %d bytes, stderr:\n%s", fetcher, o.exit, len(o.received), o.stderr)
				}
				if len(o.calls) != 2 || !strings.HasSuffix(o.calls[0], decoded.BinaryURL) || !strings.HasSuffix(o.calls[1], decoded.FallbackURL) {
					t.Fatalf("%s: the fetchers must receive the URLs verbatim: %q", fetcher, o.calls)
				}
			}
		})
	}
}

// agentUpdateFetchFragment cuts the download and digest check out of a
// rendered apply script, with the variables they read, so they run without
// systemd or /proc.
func agentUpdateFetchFragment(t *testing.T, script, work string) string {
	t.Helper()
	var header []string
	for _, line := range strings.Split(script, "\n") {
		for _, prefix := range []string{"URL=", "FALLBACK_URL=", "EXPECT_SHA="} {
			if strings.HasPrefix(line, prefix) {
				header = append(header, line)
			}
		}
	}
	start := strings.Index(script, "CANDIDATE=\"$WORK/lattice-agent\"\n")
	end := strings.Index(script, "chmod 0755 \"$CANDIDATE\"\n")
	if len(header) != 3 || start < 0 || end < start {
		t.Fatalf("cannot find the download in the script (header %q, start %d, end %d):\n%s", header, start, end, script)
	}
	return "set -e\nWORK=" + shellQuote(work) + "\n" + strings.Join(header, "\n") + "\n" + script[start:end]
}
