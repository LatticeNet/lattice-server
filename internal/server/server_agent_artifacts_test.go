package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	if err := srv.storeAgentArtifact(ref, data); err != nil {
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

	if err := srv.storeAgentArtifact(ref, data[:len(data)-1]); err == nil {
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

	// Now flip the same approval back to the upstream release and confirm the
	// lease headers disappear with it.
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	payload.BinarySource = agentBinarySourceUpstream
	payload.BinaryURL = "https://downloads.example.com/lattice-agent-linux-amd64"
	approval.Action = agentUpdateApprovalAction(payload)
	upstreamScript, err := agentUpdateApplyScript(approval, artifactTestPublicURL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(upstreamScript, "-H \""+agentTaskLeaseHeader) ||
		strings.Contains(upstreamScript, "--header=\""+agentTaskLeaseHeader) {
		t.Fatalf("an upstream download must not carry the task lease:\n%s", upstreamScript)
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
// not the authority that decides what they are.
func TestGenericStaticSurfaceRefusesTheAgentReleaseBucket(t *testing.T) {
	_, handler, _ := newAgentArtifactServer(t)
	cookies, csrf := loginSession(t, handler)

	read := doJSON(t, handler, http.MethodGet, "/api/static?bucket="+agentArtifactBucket, "", cookies, csrf)
	defer read.Body.Close()
	if read.StatusCode != http.StatusForbidden {
		t.Fatalf("reading the reserved bucket answered %d, want 403", read.StatusCode)
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
	if err := srv.storeAgentArtifact(ref, data); err != nil {
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
		Artifacts   []agentArtifactView `json:"artifacts"`
		StoredBytes int                 `json:"stored_bytes"`
		LimitBytes  int                 `json:"limit_bytes"`
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
	if bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(data)[:64])) {
		t.Fatal("the listing carried the binary content")
	}
}

// Storing a version twice replaces it, so a version never resolves to two
// different binaries and the bucket does not grow a copy per upload.
func TestStoreAgentArtifactReplacesAnEarlierDigestForTheSamePlatform(t *testing.T) {
	srv, _, _ := newAgentArtifactServer(t)
	first, firstDigest := testAgentBinary()
	if err := srv.storeAgentArtifact(agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: firstDigest}, first); err != nil {
		t.Fatal(err)
	}
	second := append(append([]byte(nil), first...), []byte("rebuilt")...)
	secondSum := sha256.Sum256(second)
	secondDigest := hex.EncodeToString(secondSum[:])
	if err := srv.storeAgentArtifact(agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: secondDigest}, second); err != nil {
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
		lastErr = srv.storeAgentArtifact(ref, filler)
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
