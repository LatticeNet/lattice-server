package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const artifactTestPublicURL = "https://lattice.example"

func newAgentArtifactServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:                   st,
		AdminPassword:           testAdminPass,
		PublicURL:               artifactTestPublicURL,
		DisableRenewalScheduler: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), st
}

func seedLinuxAgentNode(t *testing.T, st *store.Store) {
	t.Helper()
	if err := st.UpsertNode(model.Node{
		ID: "node-a", Name: "Node A", AgentVersion: "0.1.0",
		HostFacts: model.HostFacts{OS: "linux", Arch: "amd64"},
	}); err != nil {
		t.Fatal(err)
	}
}

func testAgentBinary() ([]byte, string) {
	data := bytes.Repeat([]byte("lattice-agent-binary\n"), 512)
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:])
}

// seedControlPlaneUpdate wires the whole path a node walks: a stored artifact,
// a policy pinned to its digest, an approved agent-update approval, and a task
// leased to the node. It returns the artifact bytes, its reference, and the
// live lease the apply script would present.
func seedControlPlaneUpdate(t *testing.T, srv *Server, st *store.Store) ([]byte, agentArtifactRef, model.Task) {
	t.Helper()
	seedLinuxAgentNode(t, st)
	data, digest := testAgentBinary()
	ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}
	if _, err := srv.storeAgentArtifact(ref, data); err != nil {
		t.Fatalf("store artifact: %v", err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.4",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    digest, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatalf("decode approval payload: %v", err)
	}
	if payload.BinarySource != agentBinarySourceControlPlane {
		t.Fatalf("stored artifact should have moved the plan onto the control plane, got source %q url %q",
			payload.BinarySource, payload.BinaryURL)
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
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected one leased task, got %d", len(leased))
	}
	task, ok := st.Task(leased[0].ID)
	if !ok {
		t.Fatal("leased task disappeared")
	}
	return data, ref, task
}

func getAgentBinary(t *testing.T, handler http.Handler, urlPath, taskID, lease string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, urlPath, nil)
	if taskID != "" {
		req.Header.Set(agentTaskIDHeader, taskID)
	}
	if lease != "" {
		req.Header.Set(agentTaskLeaseHeader, lease)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func lastAuditFor(st *store.Store, action string) (model.AuditEvent, bool) {
	events := st.AuditEvents()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == action {
			return events[i], true
		}
	}
	return model.AuditEvent{}, false
}

// The whole point of serving the binary ourselves is that the node stops
// depending on its own egress, so the happy path has to hand over the exact
// bytes and say so in the audit trail.
func TestAgentBinaryServesThePinnedBytesAndRecordsWhatItServed(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, ref, task := seedControlPlaneUpdate(t, srv, st)

	res := getAgentBinary(t, handler, ref.urlPath(), task.ID, task.LeaseID)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("download failed: %d %s", res.StatusCode, body)
	}
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("served %d bytes, want the %d stored bytes", len(got), len(data))
	}
	event, ok := lastAuditFor(st, "agent.binary.serve")
	if !ok {
		t.Fatal("serving a binary must be audited")
	}
	if event.Decision == "deny" {
		t.Fatalf("successful download audited as a denial: %+v", event)
	}
	for key, want := range map[string]string{
		"version": ref.Version, "os": ref.OS, "arch": ref.Arch, "sha256": ref.SHA256, "task_id": task.ID,
	} {
		if event.Metadata[key] != want {
			t.Fatalf("audit metadata %s = %q, want %q", key, event.Metadata[key], want)
		}
	}
	if event.NodeID != "node-a" {
		t.Fatalf("audit node_id = %q, want node-a", event.NodeID)
	}
}

// Serving from a closer place must not become a way to serve different bytes.
// A stored object whose content no longer hashes to the digest the plan pinned
// is a control-plane defect, and the node must never see it.
func TestAgentBinaryRefusesAStoredObjectThatDoesNotMatchItsDigest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		corrupt func(data []byte) []byte
	}{
		{"truncated", func(data []byte) []byte { return data[:len(data)/2] }},
		{"wrong bytes", func(data []byte) []byte {
			swapped := append([]byte(nil), data...)
			swapped[0] ^= 0xff
			return swapped
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, handler, st := newAgentArtifactServer(t)
			data, ref, task := seedControlPlaneUpdate(t, srv, st)

			// Corrupt the stored copy behind the store's own verification, the
			// way a bad disk or a partial write would.
			if err := st.PutStatic(model.StaticObject{
				Bucket: agentArtifactBucket, Path: ref.objectPath(),
				Content:     base64.StdEncoding.EncodeToString(tc.corrupt(data)),
				ContentType: agentArtifactContentType,
			}); err != nil {
				t.Fatal(err)
			}

			res := getAgentBinary(t, handler, ref.urlPath(), task.ID, task.LeaseID)
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusInternalServerError {
				t.Fatalf("corrupt artifact answered %d %s; it must be refused", res.StatusCode, body)
			}
			if bytes.Contains(body, []byte("lattice-agent-binary")) {
				t.Fatalf("refusal leaked artifact content: %s", body)
			}
			event, ok := lastAuditFor(st, "agent.binary.serve")
			if !ok {
				t.Fatal("a refused download must still be audited")
			}
			if event.Decision != "deny" {
				t.Fatalf("audit decision = %q, want deny: %+v", event.Decision, event)
			}
			if !strings.Contains(event.Reason, "integrity") {
				t.Fatalf("audit reason %q does not name the integrity failure", event.Reason)
			}
		})
	}
}

// The upload path is the other end of the same guarantee: bytes that do not
// hash to the declared digest never become a stored artifact, so a truncated
// transfer cannot quietly become what the fleet installs.
func TestStoreAgentArtifactRefusesBytesThatDoNotMatchTheDeclaredDigest(t *testing.T) {
	srv, _, _ := newAgentArtifactServer(t)
	data, digest := testAgentBinary()
	ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}

	if _, err := srv.storeAgentArtifact(ref, data[:len(data)-1]); err == nil {
		t.Fatal("a truncated upload was accepted")
	} else if !strings.Contains(err.Error(), "declared sha256") {
		t.Fatalf("error %q does not name the digest mismatch", err)
	}
	if _, ok := srv.storedAgentArtifact(ref.Version, ref.OS, ref.Arch); ok {
		t.Fatal("a refused upload still left an artifact behind")
	}
}

// A node must prove it is executing the update that names these bytes. Every
// way of failing that proof is a refusal, not a partial answer.
func TestAgentBinaryRequiresTheLeaseOfTheTaskThatNamesIt(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	_, ref, task := seedControlPlaneUpdate(t, srv, st)

	otherRef := agentArtifactRef{Version: "0.9.9", OS: ref.OS, Arch: ref.Arch, SHA256: ref.SHA256}
	otherArch := agentArtifactRef{Version: ref.Version, OS: ref.OS, Arch: "arm64", SHA256: ref.SHA256}

	cases := []struct {
		name    string
		urlPath string
		taskID  string
		lease   string
		status  int
	}{
		{"no credentials at all", ref.urlPath(), "", "", http.StatusForbidden},
		{"task id without a lease", ref.urlPath(), task.ID, "", http.StatusForbidden},
		{"a lease that is not this task's", ref.urlPath(), task.ID, "lease-that-was-never-issued", http.StatusForbidden},
		{"a lease against an unknown task", ref.urlPath(), "task-does-not-exist", task.LeaseID, http.StatusForbidden},
		{"a version this approval does not name", otherRef.urlPath(), task.ID, task.LeaseID, http.StatusForbidden},
		{"an architecture this node does not run", otherArch.urlPath(), task.ID, task.LeaseID, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := getAgentBinary(t, handler, tc.urlPath, tc.taskID, tc.lease)
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.status {
				t.Fatalf("answered %d %s, want %d", res.StatusCode, body, tc.status)
			}
			if bytes.Contains(body, []byte("lattice-agent-binary")) {
				t.Fatalf("a denied download leaked artifact content: %s", body)
			}
		})
	}
}

// This route is unauthenticated by construction: the credential travels inside
// the request, so anyone can reach it. Auditing every refusal one for one would
// hand an anonymous caller an unbounded write amplifier against the audit store,
// which is the abuse the shared failure throttle exists to stop.
func TestAgentBinaryDenialsDoNotLetAnAnonymousCallerFloodTheAuditLog(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	_, ref, _ := seedControlPlaneUpdate(t, srv, st)

	before := len(st.AuditEvents())
	refused := 0
	for i := 0; i < 200; i++ {
		res := getAgentBinary(t, handler, ref.urlPath(), "task-does-not-exist", "not-a-lease")
		status := res.StatusCode
		res.Body.Close()
		if status == http.StatusTooManyRequests {
			// The per-source limiter is the other half of this defense and cuts
			// in first from one address. The throttle is what survives an
			// attacker who rotates addresses past it.
			break
		}
		if status != http.StatusForbidden {
			t.Fatalf("attempt %d answered %d, want 403", i, status)
		}
		refused++
	}
	written := len(st.AuditEvents()) - before
	if refused < 10 {
		t.Fatalf("only %d refusals got through; the test cannot say anything about audit growth", refused)
	}
	if written == 0 {
		t.Fatal("a refused download must leave a trace; the throttle emits the first one")
	}
	if written >= refused {
		t.Fatalf("%d refusals wrote %d audit events; an anonymous caller must not drive audit growth one for one",
			refused, written)
	}
}

// A lease stops being a credential the moment the task stops being leased.
func TestAgentBinaryRefusesALeaseOnATaskThatIsNoLongerRunning(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	_, ref, task := seedControlPlaneUpdate(t, srv, st)

	if err := st.AddTaskResult(model.TaskResult{
		TaskID: task.ID, LeaseID: task.LeaseID, NodeID: "node-a",
		ExitCode: 0, FinishedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if done, ok := st.Task(task.ID); !ok || done.Status == model.TaskLeased {
		t.Fatalf("task should have left the leased state, got %q", done.Status)
	}
	res := getAgentBinary(t, handler, ref.urlPath(), task.ID, task.LeaseID)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a cancelled task's lease answered %d, want 403", res.StatusCode)
	}
}

// If the control plane does not hold the bytes, it says so. It does not quietly
// send the node back to the third party the approved plan moved it away from.
func TestAgentBinaryMissingArtifactIsAnErrorNotAFallback(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	_, ref, task := seedControlPlaneUpdate(t, srv, st)

	if err := st.DeleteStatic(agentArtifactBucket, ref.objectPath()); err != nil {
		t.Fatal(err)
	}
	res := getAgentBinary(t, handler, ref.urlPath(), task.ID, task.LeaseID)
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing artifact answered %d, want 404", res.StatusCode)
	}
	if location := res.Header.Get("Location"); location != "" {
		t.Fatalf("missing artifact redirected to %q; there is no silent fallback", location)
	}
	event, ok := lastAuditFor(st, "agent.binary.serve")
	if !ok || event.Decision != "deny" {
		t.Fatalf("a missing artifact must be audited as a denial, got %+v", event)
	}
}

// The lease is a live server credential. It goes to the control plane and
// nowhere else, so an upstream download must not carry it.
func TestAgentUpdateApplyScriptSendsTheLeaseOnlyToTheControlPlane(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	_, ref, task := seedControlPlaneUpdate(t, srv, st)
	_ = task

	approval, ok := controlPlaneApprovalFor(st, "node-a")
	if !ok {
		t.Fatal("expected an agent update approval for node-a")
	}
	script, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, artifactTestPublicURL+ref.urlPath()) {
		t.Fatalf("script does not download from the control plane:\n%s", script)
	}
	for _, want := range []string{agentTaskIDHeader + ": $LATTICE_TASK_ID", agentTaskLeaseHeader + ": $LATTICE_TASK_LEASE_ID"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script does not present %q:\n%s", want, script)
		}
	}
	if !strings.Contains(script, "needs node-agent v0.2.0 or newer") {
		t.Fatal("script must fail closed, with the reason named, on an agent that cannot prove its lease")
	}
	// A redirect would carry the lease headers onward: curl strips only the
	// standard Authorization header across hosts, and wget strips nothing. The
	// release URL fallback follows redirects, so it must be the one fetch that
	// carries no lease.
	credentialed := 0
	for _, line := range strings.Split(script, "\n") {
		hasLease := strings.Contains(line, agentTaskLeaseHeader)
		if !hasLease && !strings.Contains(line, "$FALLBACK_URL\"") {
			continue
		}
		fetch := strings.Contains(line, "curl ") || strings.Contains(line, "wget ")
		if !fetch {
			continue
		}
		if hasLease {
			credentialed++
			if strings.Contains(line, "curl -fsSL") || (strings.Contains(line, "wget ") && !strings.Contains(line, "--max-redirect=0")) {
				t.Fatalf("the credentialed download must not follow redirects: %s", line)
			}
			if strings.Contains(line, "$FALLBACK_URL") {
				t.Fatalf("the lease must never be sent to the fallback URL: %s", line)
			}
		}
	}
	if credentialed != 2 {
		t.Fatalf("want one credentialed curl and one credentialed wget, found %d:\n%s", credentialed, script)
	}

	// Now flip the same approval back to the upstream release and confirm the
	// lease headers disappear with it.
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	payload.BinarySource = agentBinarySourceUpstream
	payload.BinaryURL = "https://downloads.example.com/lattice-agent-linux-amd64"
	payload.FallbackURL = ""
	payload.Sources = []model.AgentUpdateSource{{Kind: model.AgentSourceKindUpstream, URL: payload.BinaryURL, Reason: "the URL the update policy pins"}}
	approval.Action = agentUpdateApprovalAction(payload)
	upstreamScript, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(upstreamScript, "-H \""+agentTaskLeaseHeader) ||
		strings.Contains(upstreamScript, "--header=\""+agentTaskLeaseHeader) {
		t.Fatalf("an upstream download must not carry the task lease:\n%s", upstreamScript)
	}
	// Upstream release assets legitimately redirect to CDN storage, and that
	// request carries no credential, so it keeps following them.
	if !strings.Contains(upstreamScript, "curl -fsSL") {
		t.Fatalf("an uncredentialed upstream download still needs to follow release redirects:\n%s", upstreamScript)
	}
}

// A plan that claims control-plane distribution but names somebody else's URL
// would send the task lease to that somebody. Refuse to render it at all.
func TestAgentUpdateApplyScriptRefusesAForeignControlPlaneURL(t *testing.T) {
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
	payload.BinaryURL = "https://attacker.example" + payload.BinaryURL[len(artifactTestPublicURL):]
	approval.Action = agentUpdateApprovalAction(payload)
	if _, err := agentUpdateApplyScript(approval, artifactTestPublicURL); err == nil {
		t.Fatal("a control-plane plan pointing at another origin must not render")
	}
}

func controlPlaneApprovalFor(st *store.Store, nodeID string) (model.Approval, bool) {
	for _, approval := range st.Approvals() {
		if approval.Plugin == agentUpdatePlugin && approval.NodeID == nodeID {
			return approval, true
		}
	}
	return model.Approval{}, false
}

// Agent binaries are installed as root on every node. A static storage scope is
// not the authority that decides what they are: static:read may see what the
// bucket holds, never the bytes, and static:write may not replace, delete or
// publish them.
func TestGenericStaticSurfaceRefusesTheAgentReleaseBucket(t *testing.T) {
	srv, handler, _ := newAgentArtifactServer(t)
	data, digest := testAgentBinary()
	ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}
	if _, err := srv.storeAgentArtifact(ref, data); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)

	read := doJSON(t, handler, http.MethodGet, "/api/static?bucket="+agentArtifactBucket, "", cookies, csrf)
	defer read.Body.Close()
	if read.StatusCode != http.StatusOK {
		t.Fatalf("listing the reserved bucket answered %d, want 200 for static:read", read.StatusCode)
	}
	var listed []model.StaticObject
	if err := json.NewDecoder(read.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Path != ref.objectPath() {
		t.Fatalf("listing = %+v, want the one stored release", listed)
	}
	if listed[0].Content != "" {
		t.Fatal("the generic listing carried the agent binary")
	}
	if listed[0].Size != len(base64.StdEncoding.EncodeToString(data)) {
		t.Fatalf("listed size %d must still say how much is stored", listed[0].Size)
	}

	del := doJSON(t, handler, http.MethodPost, "/api/static/delete",
		`{"bucket":"`+agentArtifactBucket+`","path":"`+ref.objectPath()+`"}`, cookies, csrf)
	defer del.Body.Close()
	if del.StatusCode != http.StatusForbidden {
		t.Fatalf("deleting from the reserved bucket answered %d, want 403", del.StatusCode)
	}

	write := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"`+agentArtifactBucket+`","path":"0.3.4/linux/amd64/x","content":"","content_type":"application/octet-stream"}`,
		cookies, csrf)
	defer write.Body.Close()
	if write.StatusCode != http.StatusForbidden {
		t.Fatalf("writing the reserved bucket answered %d, want 403", write.StatusCode)
	}

	binding := doJSON(t, handler, http.MethodPost, "/api/storage/bindings?kind=static",
		`{"bucket":"`+agentArtifactBucket+`","hostname":"downloads.example.com"}`, cookies, csrf)
	defer binding.Body.Close()
	if binding.StatusCode == http.StatusOK {
		t.Fatal("the reserved bucket must not be publishable through a static binding")
	}
}

// The console has to be able to see what the fleet can install without the
// listing dragging megabytes of binary through it.
func TestAgentArtifactListingReportsWhatIsAvailableWithoutTheContent(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, digest := testAgentBinary()
	ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}
	if _, err := srv.storeAgentArtifact(ref, data); err != nil {
		t.Fatal(err)
	}
	_ = st

	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodGet, "/api/nodes/agent-updates/artifacts", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("listing answered %d", res.StatusCode)
	}
	var out struct {
		Artifacts      []agentArtifactView `json:"artifacts"`
		StoredBytes    int                 `json:"stored_bytes"`
		LimitBytes     int                 `json:"limit_bytes"`
		ServingEnabled bool                `json:"serving_enabled"`
	}
	body, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Artifacts) != 1 {
		t.Fatalf("listed %d artifacts, want 1", len(out.Artifacts))
	}
	got := out.Artifacts[0]
	if got.Version != "0.3.4" || got.OS != "linux" || got.Arch != "amd64" || got.SHA256 != digest {
		t.Fatalf("listed artifact %+v does not describe what was stored", got)
	}
	if got.SizeBytes != len(data) {
		t.Fatalf("listed size %d, want %d", got.SizeBytes, len(data))
	}
	if out.LimitBytes != maxAgentArtifactStoreBytes || out.StoredBytes <= 0 {
		t.Fatalf("listing must report the storage budget, got stored=%d limit=%d", out.StoredBytes, out.LimitBytes)
	}
	if !out.ServingEnabled {
		t.Fatal("a server with an https public URL can serve, and the listing must say so")
	}
	if bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(data)[:64])) {
		t.Fatal("the listing carried the binary content")
	}
}

// A stored artifact is useless without a public HTTPS base to hand nodes, and
// the plan quietly stays upstream in that case. The console has to be able to
// tell the two situations apart.
func TestAgentArtifactListingSaysWhenItCannotServeWhatItHolds(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	data, digest := testAgentBinary()
	if _, err := srv.storeAgentArtifact(agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}, data); err != nil {
		t.Fatal(err)
	}
	seedLinuxAgentNode(t, st)
	if _, ok := srv.controlPlaneAgentArtifact("0.3.4", "linux", "amd64", digest); ok {
		t.Fatal("without an https public URL there is no address a node can be sent to")
	}

	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodGet, "/api/nodes/agent-updates/artifacts", "", cookies, csrf)
	defer res.Body.Close()
	var out struct {
		Artifacts      []agentArtifactView `json:"artifacts"`
		ServingEnabled bool                `json:"serving_enabled"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Artifacts) != 1 {
		t.Fatalf("the artifact is stored and must still be listed, got %d", len(out.Artifacts))
	}
	if out.ServingEnabled {
		t.Fatal("the listing claimed it can serve an artifact it has no address for")
	}
}

// Storing a version twice replaces it, so a version never resolves to two
// different binaries and the bucket does not grow a copy per upload.
func TestStoreAgentArtifactReplacesAnEarlierDigestForTheSamePlatform(t *testing.T) {
	srv, _, _ := newAgentArtifactServer(t)
	first, firstDigest := testAgentBinary()
	if _, err := srv.storeAgentArtifact(agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: firstDigest}, first); err != nil {
		t.Fatal(err)
	}
	second := append(append([]byte(nil), first...), []byte("rebuilt")...)
	secondSum := sha256.Sum256(second)
	secondDigest := hex.EncodeToString(secondSum[:])
	if _, err := srv.storeAgentArtifact(agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: secondDigest}, second); err != nil {
		t.Fatal(err)
	}
	artifacts := srv.agentArtifacts()
	if len(artifacts) != 1 {
		t.Fatalf("expected one artifact for the platform, got %d", len(artifacts))
	}
	if artifacts[0].SHA256 != secondDigest {
		t.Fatalf("stored digest %s, want the replacement %s", artifacts[0].SHA256, secondDigest)
	}
}

// Storage is bounded and says so. It refuses the write rather than evicting a
// binary some queued approval is still counting on.
func TestStoreAgentArtifactRefusesToGrowPastItsCap(t *testing.T) {
	srv, _, _ := newAgentArtifactServer(t)
	filler := bytes.Repeat([]byte("x"), maxAgentArtifactBytes)
	fillerSum := sha256.Sum256(filler)
	fillerDigest := hex.EncodeToString(fillerSum[:])
	// Three near-cap objects across distinct platforms and versions overrun the
	// bucket budget on the base64 form.
	refs := []agentArtifactRef{
		{Version: "0.3.1", OS: "linux", Arch: "amd64", SHA256: fillerDigest},
		{Version: "0.3.2", OS: "linux", Arch: "amd64", SHA256: fillerDigest},
		{Version: "0.3.3", OS: "linux", Arch: "amd64", SHA256: fillerDigest},
	}
	var lastErr error
	for _, ref := range refs {
		_, lastErr = srv.storeAgentArtifact(ref, filler)
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("the bucket grew past its cap without complaint")
	}
	if !strings.Contains(lastErr.Error(), "cap") {
		t.Fatalf("error %q does not explain the storage cap", lastErr)
	}
}

// A full artifact store answers 507 with the usage and the way out. Every
// other 5xx keeps its masked message: only the store-full error is marked as
// written for the operator.
func TestAgentArtifactStoreFullTellsTheOperatorWhatToDo(t *testing.T) {
	_, handler, st := newAgentArtifactServer(t)
	const used = maxAgentArtifactStoreBytes - 1024
	if err := st.PutStatic(model.StaticObject{
		Bucket: agentArtifactBucket, Path: "0.3.1/linux/arm64/" + strings.Repeat("a", 64),
		Content: strings.Repeat("A", used), ContentType: agentArtifactContentType,
	}); err != nil {
		t.Fatal(err)
	}
	data, digest := testAgentBinary()
	cookies, csrf := loginSession(t, handler)
	req := httptest.NewRequest(http.MethodPost, "/api/nodes/agent-updates/artifacts?version=0.3.4&os=linux&arch=amd64&sha256="+digest, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Lattice-CSRF", csrf)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("upload into a full store: %d %s", rec.Code, rec.Body.String())
	}
	var body model.APIErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodedLen(len(data))
	for _, want := range []string{
		"agent release storage is full",
		strconv.Itoa(used) + " of the " + strconv.Itoa(maxAgentArtifactStoreBytes) + " byte cap is in use",
		"needs " + strconv.Itoa(encoded) + " more",
		"delete a stored artifact first",
	} {
		if !strings.Contains(body.Error.Message, want) {
			t.Fatalf("message %q lacks %q", body.Error.Message, want)
		}
	}
	if len(st.Static(agentArtifactBucket)) != 1 {
		t.Fatal("a refused upload was stored")
	}

	// The mask still holds for every other server error, 507 included.
	for _, tc := range []struct {
		status int
		err    error
		want   string
	}{
		{http.StatusInternalServerError, errors.New("open /var/lib/lattice/state.json: permission denied"), "internal server error"},
		{http.StatusInsufficientStorage, errors.New("disk /dev/sda1 is full"), "internal server error"},
		{http.StatusBadGateway, errors.New("dial tcp 10.0.0.1:443: refused"), "upstream service error"},
		{http.StatusInternalServerError, fmt.Errorf("store: %w", errAgentArtifactStoreFull), "internal server error"},
	} {
		rec := httptest.NewRecorder()
		writeError(rec, tc.status, tc.err)
		var got model.APIErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Error.Message != tc.want {
			t.Fatalf("%d %q answered %q, want %q", tc.status, tc.err, got.Error.Message, tc.want)
		}
	}
}

func getAgentBinaryWith(t *testing.T, handler http.Handler, method, urlPath, taskID, lease string, header map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, urlPath, nil)
	if taskID != "" {
		req.Header.Set(agentTaskIDHeader, taskID)
	}
	if lease != "" {
		req.Header.Set(agentTaskLeaseHeader, lease)
	}
	for key, value := range header {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

// A node on a slow uplink continues a cut download with a range request. The
// route answers single ranges with 206 and the exact bytes, names the pinned
// digest as a strong ETag, and answers anything it cannot serve as a range
// in a way that never hands back a slice of different bytes.
func TestAgentBinaryServesByteRanges(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, ref, task := seedControlPlaneUpdate(t, srv, st)
	size := len(data)
	etag := `"` + ref.SHA256 + `"`

	for _, tc := range []struct {
		name         string
		method       string
		header       map[string]string
		status       int
		body         []byte
		contentRange string
	}{
		{"a middle range", http.MethodGet, map[string]string{"Range": "bytes=100-199"}, http.StatusPartialContent,
			data[100:200], fmt.Sprintf("bytes 100-199/%d", size)},
		{"the rest from an offset, as curl -C - and wget -c ask", http.MethodGet, map[string]string{"Range": "bytes=4000-"}, http.StatusPartialContent,
			data[4000:], fmt.Sprintf("bytes 4000-%d/%d", size-1, size)},
		{"a suffix range", http.MethodGet, map[string]string{"Range": "bytes=-100"}, http.StatusPartialContent,
			data[size-100:], fmt.Sprintf("bytes %d-%d/%d", size-100, size-1, size)},
		{"If-Range naming the pinned digest resumes", http.MethodGet, map[string]string{"Range": "bytes=4000-", "If-Range": etag}, http.StatusPartialContent,
			data[4000:], fmt.Sprintf("bytes 4000-%d/%d", size-1, size)},
		{"If-Range naming other bytes gets the whole object", http.MethodGet,
			map[string]string{"Range": "bytes=4000-", "If-Range": `"` + strings.Repeat("0", 64) + `"`}, http.StatusOK, data, ""},
		{"a weak If-Range gets the whole object", http.MethodGet, map[string]string{"Range": "bytes=4000-", "If-Range": "W/" + etag}, http.StatusOK, data, ""},
		{"a date If-Range gets the whole object", http.MethodGet,
			map[string]string{"Range": "bytes=4000-", "If-Range": time.Now().UTC().Format(http.TimeFormat)}, http.StatusOK, data, ""},
		{"a range past the end", http.MethodGet, map[string]string{"Range": fmt.Sprintf("bytes=%d-", size)}, http.StatusRequestedRangeNotSatisfiable,
			nil, fmt.Sprintf("bytes */%d", size)},
		{"several ranges get the whole object once", http.MethodGet, map[string]string{"Range": "bytes=0-9,0-9,0-9,0-9"}, http.StatusOK, data, ""},
		{"no range", http.MethodGet, nil, http.StatusOK, data, ""},
		{"HEAD", http.MethodHead, nil, http.StatusOK, nil, ""},
		{"HEAD with a range", http.MethodHead, map[string]string{"Range": "bytes=4000-"}, http.StatusPartialContent,
			nil, fmt.Sprintf("bytes 4000-%d/%d", size-1, size)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := getAgentBinaryWith(t, handler, tc.method, ref.urlPath(), task.ID, task.LeaseID, tc.header)
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tc.status {
				t.Fatalf("answered %d, want %d: %s", res.StatusCode, tc.status, body)
			}
			if tc.status == http.StatusRequestedRangeNotSatisfiable {
				body = nil
			}
			if !bytes.Equal(body, tc.body) {
				t.Fatalf("served %d bytes, want %d", len(body), len(tc.body))
			}
			if got := res.Header.Get("Content-Range"); got != tc.contentRange {
				t.Fatalf("Content-Range = %q, want %q", got, tc.contentRange)
			}
			if tc.status != http.StatusRequestedRangeNotSatisfiable {
				if got := res.Header.Get("ETag"); got != etag {
					t.Fatalf("ETag = %q, want the pinned digest %q", got, etag)
				}
				if res.Header.Get("Accept-Ranges") != "bytes" || res.Header.Get("Cache-Control") != "no-store" ||
					res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("Content-Type") != agentArtifactContentType {
					t.Fatalf("headers lost: %v", res.Header)
				}
				want := len(tc.body)
				if tc.method == http.MethodHead {
					want = size
					if tc.contentRange != "" {
						want = size - 4000
					}
				}
				if res.Header.Get("Content-Length") != strconv.Itoa(want) {
					t.Fatalf("Content-Length = %q, want %d", res.Header.Get("Content-Length"), want)
				}
			}
		})
	}
	if event, ok := servedRangeAudit(st, "bytes=4000-"); !ok || event.Metadata["bytes"] != strconv.Itoa(size) || event.Metadata["task_id"] != task.ID {
		t.Fatalf("a served range must be audited with the range asked for: %+v", event)
	}
	if event, ok := servedRangeAudit(st, "bytes=0-9,0-9,0-9,0-9"); !ok || event.Metadata["range_ignored"] == "" {
		t.Fatalf("a multi-range request must be audited with what it asked for and that it was served whole: %+v", event)
	}
}

// deadlineRecorder is a response recorder that takes a write deadline, as the
// server's own connection writer does.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

// The server's 60 s write timeout would cut a direct connection to a slow
// node about a megabyte in. The binary route lifts it to the update task's
// own timeout, through every wrapper the handler chain puts in between, and
// only for a caller that proved its lease.
func TestAgentBinaryOutlastsTheServerWriteTimeout(t *testing.T) {
	srv, handler, st := newAgentArtifactServer(t)
	data, ref, task := seedControlPlaneUpdate(t, srv, st)
	serve := func(lease string) *deadlineRecorder {
		req := httptest.NewRequest(http.MethodGet, ref.urlPath(), nil)
		req.Header.Set(agentTaskIDHeader, task.ID)
		req.Header.Set(agentTaskLeaseHeader, lease)
		rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		handler.ServeHTTP(rec, req)
		return rec
	}
	before := time.Now()
	rec := serve(task.LeaseID)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), data) {
		t.Fatalf("download answered %d with %d bytes", rec.Code, rec.Body.Len())
	}
	budget := time.Duration(approvalApplyTaskTimeoutSec(agentUpdatePlugin)) * time.Second
	if rec.deadline.Before(before.Add(budget)) || rec.deadline.After(time.Now().Add(budget)) {
		t.Fatalf("write deadline %v, want about %v from now", rec.deadline, budget)
	}
	if denied := serve("not-a-lease"); denied.Code != http.StatusForbidden || !denied.deadline.IsZero() {
		t.Fatalf("a refused caller must keep the server's deadline: %d, deadline %v", denied.Code, denied.deadline)
	}
}

// servedRangeAudit finds the serve audit for one range request.
func servedRangeAudit(st *store.Store, requested string) (model.AuditEvent, bool) {
	for _, event := range st.AuditEvents() {
		if event.Action == "agent.binary.serve" && event.Decision != "deny" && event.Metadata["range"] == requested {
			return event, true
		}
	}
	return model.AuditEvent{}, false
}

// A range request is held to every check a full one is, before any byte goes
// out: the lease, the node's own artifact, the integrity of the stored copy,
// and the denial audit throttle.
func TestAgentBinaryRangeRequestsPassTheSameChecks(t *testing.T) {
	rangeHeader := map[string]string{"Range": "bytes=10-"}
	t.Run("lease and artifact", func(t *testing.T) {
		srv, handler, st := newAgentArtifactServer(t)
		_, ref, task := seedControlPlaneUpdate(t, srv, st)
		otherArch := agentArtifactRef{Version: ref.Version, OS: ref.OS, Arch: "arm64", SHA256: ref.SHA256}
		for name, req := range map[string]struct{ path, taskID, lease string }{
			"no credentials":    {ref.urlPath(), "", ""},
			"a foreign lease":   {ref.urlPath(), task.ID, "lease-that-was-never-issued"},
			"another platform":  {otherArch.urlPath(), task.ID, task.LeaseID},
			"an unknown task":   {ref.urlPath(), "task-does-not-exist", task.LeaseID},
			"a task id, no key": {ref.urlPath(), task.ID, ""},
		} {
			res := getAgentBinaryWith(t, handler, http.MethodGet, req.path, req.taskID, req.lease, rangeHeader)
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != http.StatusForbidden || bytes.Contains(body, []byte("lattice-agent-binary")) {
				t.Fatalf("%s: a range request answered %d %s, want 403 and no bytes", name, res.StatusCode, body)
			}
		}
	})
	t.Run("integrity", func(t *testing.T) {
		srv, handler, st := newAgentArtifactServer(t)
		data, ref, task := seedControlPlaneUpdate(t, srv, st)
		if err := st.PutStatic(model.StaticObject{
			Bucket: agentArtifactBucket, Path: ref.objectPath(),
			Content:     base64.StdEncoding.EncodeToString(data[:len(data)-1]),
			ContentType: agentArtifactContentType,
		}); err != nil {
			t.Fatal(err)
		}
		res := getAgentBinaryWith(t, handler, http.MethodGet, ref.urlPath(), task.ID, task.LeaseID, rangeHeader)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusInternalServerError || bytes.Contains(body, []byte("lattice-agent-binary")) {
			t.Fatalf("a range of a corrupt object answered %d %s; it must be refused whole", res.StatusCode, body)
		}
	})
	t.Run("denial audit throttle", func(t *testing.T) {
		srv, handler, st := newAgentArtifactServer(t)
		_, ref, _ := seedControlPlaneUpdate(t, srv, st)
		before := len(st.AuditEvents())
		refused := 0
		for i := 0; i < 200; i++ {
			res := getAgentBinaryWith(t, handler, http.MethodGet, ref.urlPath(), "task-does-not-exist", "not-a-lease", rangeHeader)
			status := res.StatusCode
			res.Body.Close()
			if status == http.StatusTooManyRequests {
				break
			}
			if status != http.StatusForbidden {
				t.Fatalf("attempt %d answered %d, want 403", i, status)
			}
			refused++
		}
		if written := len(st.AuditEvents()) - before; refused < 10 || written == 0 || written >= refused {
			t.Fatalf("%d refused range requests wrote %d audit events; the throttle must hold", refused, written)
		}
	})
}

// The per-source route limiter counts a range request exactly as it counts a
// full download: one request, one token. A resuming node costs the limiter no
// more than a node that starts over, and a caller cannot buy extra requests
// by asking for small pieces.
func TestAgentBinaryRangeRequestsCostTheLimiterWhatAFullOneDoes(t *testing.T) {
	count := func(header map[string]string) int {
		srv, handler, st := newAgentArtifactServer(t)
		_, ref, task := seedControlPlaneUpdate(t, srv, st)
		for i := 0; i < 500; i++ {
			res := getAgentBinaryWith(t, handler, http.MethodGet, ref.urlPath(), task.ID, task.LeaseID, header)
			status := res.StatusCode
			res.Body.Close()
			if status == http.StatusTooManyRequests {
				return i
			}
			if status != http.StatusOK && status != http.StatusPartialContent {
				t.Fatalf("request %d answered %d", i, status)
			}
		}
		t.Fatal("the route limiter never cut in")
		return 0
	}
	full := count(nil)
	ranged := count(map[string]string{"Range": "bytes=0-0"})
	if full == 0 || ranged != full {
		t.Fatalf("one source got %d full downloads but %d one-byte ranges before the limiter cut in; they must cost the same", full, ranged)
	}
}
