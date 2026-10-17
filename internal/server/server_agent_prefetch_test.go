package server

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/ratelimit"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// seedPrefetchNode stores a linux/amd64 node with a token whose hash takes
// one PBKDF2 iteration, as seedFleetNode does, and returns the token.
func seedPrefetchNode(t *testing.T, st *store.Store, nodeID string) string {
	t.Helper()
	token := "prefetch-token-" + nodeID
	salt := []byte("prefetch-salt-" + nodeID)
	key, err := pbkdf2.Key(sha256.New, token, salt, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("pbkdf2-sha256$1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	if err := st.UpsertNode(model.Node{
		ID: nodeID, Name: nodeID, AgentVersion: "0.1.0", TokenHash: hash,
		HostFacts: model.HostFacts{OS: "linux", Arch: "amd64"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return token
}

type prefetchFixture struct {
	srv      *Server
	handler  http.Handler
	st       *store.Store
	data     []byte
	served   []byte
	ref      agentArtifactRef
	approval model.Approval
	token    string
	// header is sent with a refusal case's request.
	header map[string]string
}

// newPrefetchFixture is a control plane holding the binary, raw or as an
// import stores it, and a pending agent update for node-a planned now, which
// fetches from the control plane under the source walk. The agent limiter is
// opened up so a test can make as many requests as it needs from one address.
func newPrefetchFixture(t *testing.T, size int, compressed bool) *prefetchFixture {
	t.Helper()
	srv, handler, st := newAgentArtifactServer(t)
	srv.agentLimiter = ratelimit.New(ratelimit.Config{Rate: 1e6, Burst: 1e6})
	token := seedPrefetchNode(t, st, "node-a")
	data, _ := walkTestBinary("0.3.4", size)
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
	if approval.Status != model.ApprovalPending {
		t.Fatalf("a new plan must be pending, got %q", approval.Status)
	}
	obj, _ := st.StaticObject(agentArtifactBucket, ref.objectPath())
	served, _ := base64.StdEncoding.DecodeString(obj.Content)
	return &prefetchFixture{srv: srv, handler: handler, st: st, data: data, served: served, ref: ref, approval: approval, token: token}
}

func (f *prefetchFixture) setStatus(t *testing.T, status, reason string) {
	t.Helper()
	f.approval.Status, f.approval.Reason = status, reason
	if err := f.st.UpsertApproval(f.approval); err != nil {
		t.Fatal(err)
	}
}

// approveWithTask approves the plan and queues its apply task, leased to the
// node when lease is set.
func (f *prefetchFixture) approveWithTask(t *testing.T, lease bool) model.Task {
	t.Helper()
	f.setStatus(t, model.ApprovalApproved, "")
	task := model.Task{
		ID: id.New("task"), ApprovalID: f.approval.ID, Targets: []string{"node-a"},
		Interpreter: "sh", Script: "true", TimeoutSec: 600, OutputLimit: 65536,
		Status: model.TaskQueued, CreatedAt: time.Now().UTC(),
	}
	if err := f.st.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if !lease {
		return task
	}
	leased, err := f.st.LeaseTasks("node-a", 1)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease the apply task: %v %d", err, len(leased))
	}
	task, _ = f.st.Task(leased[0].ID)
	return task
}

func prefetchPath(ref agentArtifactRef, nodeID string) string {
	return agentPrefetchPathPrefix + ref.objectPath() + "?node_id=" + nodeID
}

func (f *prefetchFixture) get(t *testing.T, path, token string, header map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec.Result()
}

type prefetchConfigBody struct {
	Debug               json.RawMessage `json:"debug"`
	LatticeIdentityUUID string          `json:"lattice_identity_uuid"`
	AgentUpdate         *struct {
		Prefetch *agentPrefetchTarget `json:"prefetch"`
		Keep     []string             `json:"keep"`
	} `json:"agent_update"`
}

func (f *prefetchFixture) config(t *testing.T) prefetchConfigBody {
	t.Helper()
	res := f.get(t, "/api/agent/config?node_id=node-a", f.token, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("config pull: %d", res.StatusCode)
	}
	var out prefetchConfigBody
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.AgentUpdate == nil || out.AgentUpdate.Keep == nil {
		t.Fatal("a server that serves prefetch must always send agent_update with a keep list")
	}
	if len(out.Debug) == 0 || out.LatticeIdentityUUID == "" {
		t.Fatalf("the SDK's config fields must still be sent: %+v", out)
	}
	return out
}

// The config pull names the open approval's file by digests and sizes, and
// never a URL: the agent builds the URL from its own server address.
func TestAgentPrefetchConfigNamesTheOpenApprovalsFile(t *testing.T) {
	for _, compressed := range []bool{true, false} {
		t.Run(fmt.Sprintf("compressed=%v", compressed), func(t *testing.T) {
			f := newPrefetchFixture(t, 64<<10, compressed)
			got := f.config(t).AgentUpdate
			want := agentPrefetchTarget{
				ApprovalID: f.approval.ID, Version: "0.3.4", OS: "linux", Arch: "amd64",
				SHA256: f.ref.SHA256, CompressedSHA256: f.ref.GzipSHA256,
				Size: len(f.served), BinarySize: len(f.data), InstallPath: defaultAgentInstallPath,
			}
			if got.Prefetch == nil || *got.Prefetch != want {
				t.Fatalf("prefetch %+v, want %+v", got.Prefetch, want)
			}
			wantKeep := []string{f.ref.SHA256}
			if compressed {
				wantKeep = append(wantKeep, f.ref.GzipSHA256)
				if len(f.served) >= len(f.data) {
					t.Fatal("the compressed object must be what is fetched")
				}
			}
			if !slices.Equal(got.Keep, wantKeep) {
				t.Fatalf("keep %v, want %v", got.Keep, wantKeep)
			}
			raw, _ := json.Marshal(got.Prefetch)
			if strings.Contains(string(raw), "http") {
				t.Fatalf("the prefetch block must carry no URL: %s", raw)
			}
		})
	}
}

// Prefetch is withheld whenever the task could not use the file, and keep
// still names every pending or approved update's digests, so a running
// update's download is never pruned.
func TestAgentPrefetchConfigWithholdsWhatTheTaskWouldNotUse(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, f *prefetchFixture)
		prefetch bool
		keep     bool
	}{
		{"pending", func(t *testing.T, f *prefetchFixture) {}, true, true},
		{"approved with its task queued", func(t *testing.T, f *prefetchFixture) { f.approveWithTask(t, false) }, true, true},
		{"approved with its task running", func(t *testing.T, f *prefetchFixture) { f.approveWithTask(t, true) }, false, true},
		{"run and awaiting the node's confirmation", func(t *testing.T, f *prefetchFixture) {
			f.setStatus(t, model.ApprovalApproved, agentUpdateAwaitingConfirmationReason("0.3.4"))
		}, false, true},
		{"rejected", func(t *testing.T, f *prefetchFixture) { f.setStatus(t, model.ApprovalRejected, "no") }, false, false},
		{"applied", func(t *testing.T, f *prefetchFixture) { f.setStatus(t, model.ApprovalApplied, "") }, false, false},
		{"the node already runs the target", func(t *testing.T, f *prefetchFixture) {
			node, _ := f.st.Node("node-a")
			node.AgentVersion = "v0.3.4"
			if err := f.st.UpsertNode(node); err != nil {
				t.Fatal(err)
			}
		}, false, true},
		{"the control plane no longer holds the object", func(t *testing.T, f *prefetchFixture) {
			if err := f.st.DeleteStatic(agentArtifactBucket, f.ref.objectPath()); err != nil {
				t.Fatal(err)
			}
		}, false, true},
		{"task execution is disabled", func(t *testing.T, f *prefetchFixture) { f.srv.taskExecutionDisabled = true }, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrefetchFixture(t, 64<<10, true)
			tc.setup(t, f)
			got := f.config(t).AgentUpdate
			if (got.Prefetch != nil) != tc.prefetch {
				t.Fatalf("prefetch %+v, want present=%v", got.Prefetch, tc.prefetch)
			}
			if wantKeep := tc.keep; (len(got.Keep) == 2) != wantKeep || (!wantKeep && len(got.Keep) != 0) {
				t.Fatalf("keep %v, want the plan's two digests=%v", got.Keep, tc.keep)
			}
		})
	}
	t.Run("a plan made before the source walk", func(t *testing.T) {
		f := newPrefetchFixture(t, 64<<10, false)
		f.approval.Plan = strings.Replace(f.approval.Plan, agentUpdateCutoffPlanLine+"\n", "", 1)
		f.setStatus(t, model.ApprovalPending, "")
		if got := f.config(t).AgentUpdate; got.Prefetch != nil || len(got.Keep) != 1 {
			t.Fatalf("an S1 script asks for a range past a complete file, so its plan is never prefetched: %+v", got)
		}
	})
	t.Run("a plan fetching upstream", func(t *testing.T) {
		f := newPrefetchFixture(t, 64<<10, false)
		payload, err := agentUpdatePayloadFromApproval(f.approval)
		if err != nil {
			t.Fatal(err)
		}
		payload.BinarySource, payload.BinaryURL, payload.FallbackURL = "", fallbackTestReleaseURL, ""
		f.approval.Action = agentUpdateApprovalAction(payload)
		f.setStatus(t, model.ApprovalPending, "")
		if got := f.config(t).AgentUpdate; got.Prefetch != nil {
			t.Fatalf("prefetch fetches from the control plane only: %+v", got.Prefetch)
		}
	})
}

// The route serves the open approval's object to its node, on the node
// credential, with ranges and the served digest as ETag, and audits it as a
// prefetch.
func TestAgentPrefetchRouteServesTheOpenApprovalsObject(t *testing.T) {
	f := newPrefetchFixture(t, 64<<10, true)
	path := prefetchPath(f.ref, "node-a")
	etag := `"` + f.ref.GzipSHA256 + `"`

	res := f.get(t, path, f.token, nil)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != string(f.served) || res.Header.Get("ETag") != etag ||
		res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Encoding") != "" {
		t.Fatalf("status %d, %d bytes, etag %q", res.StatusCode, len(body), res.Header.Get("ETag"))
	}
	ev, ok := lastAuditFor(f.st, "agent.binary.prefetch")
	if !ok || ev.Decision == "deny" || ev.Metadata["approval_id"] != f.approval.ID || ev.Metadata["compressed_sha256"] != f.ref.GzipSHA256 || ev.Metadata["task_id"] != "" {
		t.Fatalf("the serve must be audited as a prefetch for its approval: %+v", ev)
	}

	res = f.get(t, path, f.token, map[string]string{"Range": "bytes=100-", "If-Range": etag})
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusPartialContent || string(body) != string(f.served[100:]) ||
		res.Header.Get("Content-Range") != fmt.Sprintf("bytes 100-%d/%d", len(f.served)-1, len(f.served)) {
		t.Fatalf("a range must continue the served bytes: status %d %q", res.StatusCode, res.Header.Get("Content-Range"))
	}
	res = f.get(t, path, f.token, map[string]string{"Range": "bytes=100-", "If-Range": `"` + f.ref.SHA256 + `"`})
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || len(body) != len(f.served) {
		t.Fatalf("an If-Range naming other bytes must get the whole object: status %d", res.StatusCode)
	}

	// An open approval that is approved but not yet running still counts.
	f.approveWithTask(t, false)
	res = f.get(t, path, f.token, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an approved plan whose task is only queued must still be served, got %d", res.StatusCode)
	}
}

// Nothing but the node's own open approval's object is ever served, and
// never on anything but the node's own credential.
func TestAgentPrefetchRouteRefusesEverythingElse(t *testing.T) {
	other := sha256.Sum256([]byte("other"))
	otherHex := hex.EncodeToString(other[:])
	cases := []struct {
		name   string
		setup  func(t *testing.T, f *prefetchFixture)
		path   func(f *prefetchFixture) string
		token  func(f *prefetchFixture) string
		status int
	}{
		{name: "no credential", token: func(*prefetchFixture) string { return "" }, status: http.StatusUnauthorized},
		{name: "a wrong token", token: func(*prefetchFixture) string { return "not-the-token" }, status: http.StatusUnauthorized},
		{name: "a live task lease instead of the node credential", setup: func(t *testing.T, f *prefetchFixture) {
			task := f.approveWithTask(t, true)
			f.header = map[string]string{agentTaskIDHeader: task.ID, agentTaskLeaseHeader: task.LeaseID}
		}, token: func(*prefetchFixture) string { return "" }, status: http.StatusUnauthorized},
		{name: "another node's credential for this node", setup: func(t *testing.T, f *prefetchFixture) { seedPrefetchNode(t, f.st, "node-b") },
			token: func(*prefetchFixture) string { return "prefetch-token-node-b" }, status: http.StatusUnauthorized},
		{name: "another node asking for this node's binary", setup: func(t *testing.T, f *prefetchFixture) { seedPrefetchNode(t, f.st, "node-b") },
			path: func(f *prefetchFixture) string { return prefetchPath(f.ref, "node-b") }, token: func(*prefetchFixture) string { return "prefetch-token-node-b" }, status: http.StatusForbidden},
		{name: "the raw object of a compressed plan", path: func(f *prefetchFixture) string {
			raw := f.ref
			raw.GzipSHA256 = ""
			return prefetchPath(raw, "node-a")
		}, status: http.StatusForbidden},
		{name: "another digest", path: func(f *prefetchFixture) string {
			ref := f.ref
			ref.SHA256 = otherHex
			return prefetchPath(ref, "node-a")
		}, status: http.StatusForbidden},
		{name: "another version", path: func(f *prefetchFixture) string {
			ref := f.ref
			ref.Version = "0.3.3"
			return prefetchPath(ref, "node-a")
		}, status: http.StatusForbidden},
		{name: "another platform", path: func(f *prefetchFixture) string {
			ref := f.ref
			ref.Arch = "arm64"
			return prefetchPath(ref, "node-a")
		}, status: http.StatusForbidden},
		{name: "a rejected approval", setup: func(t *testing.T, f *prefetchFixture) { f.setStatus(t, model.ApprovalRejected, "no") }, status: http.StatusForbidden},
		{name: "an applied approval", setup: func(t *testing.T, f *prefetchFixture) { f.setStatus(t, model.ApprovalApplied, "") }, status: http.StatusForbidden},
		{name: "a running approval", setup: func(t *testing.T, f *prefetchFixture) { f.approveWithTask(t, true) }, status: http.StatusForbidden},
		{name: "a disabled node", setup: func(t *testing.T, f *prefetchFixture) {
			node, _ := f.st.Node("node-a")
			node.Disabled = true
			if err := f.st.UpsertNode(node); err != nil {
				t.Fatal(err)
			}
		}, status: http.StatusUnauthorized},
		{name: "a path that is not an object", path: func(*prefetchFixture) string {
			return agentPrefetchPathPrefix + "0.3.4/linux/amd64/not-a-digest?node_id=node-a"
		}, status: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrefetchFixture(t, 16<<10, true)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			path := prefetchPath(f.ref, "node-a")
			if tc.path != nil {
				path = tc.path(f)
			}
			token := f.token
			if tc.token != nil {
				token = tc.token(f)
			}
			res := f.get(t, path, token, f.header)
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %s", res.StatusCode, tc.status, body)
			}
			if strings.Contains(string(body), string(f.served[:64])) {
				t.Fatal("a refusal must carry none of the binary")
			}
			if tc.status == http.StatusForbidden {
				if ev, ok := lastAuditFor(f.st, "agent.binary.prefetch"); !ok || ev.Decision != "deny" || ev.Reason == "" {
					t.Fatalf("a refused prefetch must be audited with its reason: %+v", ev)
				}
			}
		})
	}
}

// The route shares the agent routes' per-address limiter with the binary
// route, and holds one node to agentPrefetchMaxInFlight open downloads.
func TestAgentPrefetchRouteIsRateLimitedLikeTheBinaryRoute(t *testing.T) {
	f := newPrefetchFixture(t, 16<<10, true)
	f.srv.agentLimiter = ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: 1})
	res := f.get(t, prefetchPath(f.ref, "node-a"), f.token, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the first request must be served, got %d", res.StatusCode)
	}
	for name, path := range map[string]string{
		"prefetch": prefetchPath(f.ref, "node-a"),
		"binary":   f.ref.urlPath(),
	} {
		res := f.get(t, path, f.token, nil)
		res.Body.Close()
		if res.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("the %s route must answer the shared limiter, got %d", name, res.StatusCode)
		}
	}

	f.srv.agentLimiter = ratelimit.New(ratelimit.Config{Rate: 1e6, Burst: 1e6})
	for range agentPrefetchMaxInFlight {
		if !f.srv.agentPrefetch.enter("node-a") {
			t.Fatal("enter")
		}
	}
	res = f.get(t, prefetchPath(f.ref, "node-a"), f.token, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Fatalf("a node at its in-flight bound must be told to retry, got %d", res.StatusCode)
	}
	f.srv.agentPrefetch.leave("node-a")
	res = f.get(t, prefetchPath(f.ref, "node-a"), f.token, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a freed slot must serve again, got %d", res.StatusCode)
	}
}

// Every download shares one verified copy of an object, decoded once even
// under concurrent misses; a replaced object, or one that fails its digest,
// is decoded and checked afresh, and the cache stays within its budget.
func TestAgentArtifactByteCacheSharesOneVerifiedCopy(t *testing.T) {
	c := agentArtifactByteCache{budget: 40}
	first, second := []byte("first object, twenty"), []byte("second object, twent")
	a, b := base64.StdEncoding.EncodeToString(first), base64.StdEncoding.EncodeToString(second)
	da, db := sha256.Sum256(first), sha256.Sum256(second)
	digestA, digestB := hex.EncodeToString(da[:]), hex.EncodeToString(db[:])

	var wg sync.WaitGroup
	got := make([][]byte, 16)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], _ = c.verified("p/a", a, digestA)
		}(i)
	}
	wg.Wait()
	for _, g := range got {
		if len(g) == 0 || &g[0] != &got[0][0] {
			t.Fatal("concurrent downloads of one object must share one decoded copy")
		}
	}
	if _, err := c.verified("p/a", b, digestA); err == nil || !strings.Contains(err.Error(), "does not match the pinned") {
		t.Fatalf("replaced content must be held to the digest afresh: %v", err)
	}
	if got, err := c.verified("p/a", b, digestB); err != nil || string(got) != string(second) {
		t.Fatalf("replaced content must be decoded afresh: %q %v", got, err)
	}
	c.verified("p/b", a, digestA)
	c.verified("p/c", a, digestA)
	if len(c.entries) != 2 {
		t.Fatalf("the cache must stay within its budget: %d entries", len(c.entries))
	}
	if _, err := c.verified("p/d", "not base64!", digestA); err == nil {
		t.Fatal("undecodable content must fail")
	}
}

// The config pull reads open approvals from an index a few seconds old, so
// one walk of the approval table serves every node; the route reads fresh.
func TestAgentPrefetchConfigIndexIsShortLived(t *testing.T) {
	f := newPrefetchFixture(t, 16<<10, true)
	now := time.Now()
	f.srv.now = func() time.Time { return now }
	if got := f.config(t).AgentUpdate; got.Prefetch == nil {
		t.Fatal("the open plan must be named")
	}
	f.setStatus(t, model.ApprovalRejected, "no")
	if got := f.config(t).AgentUpdate; got.Prefetch != nil || len(got.Keep) != 2 {
		t.Fatalf("inside its TTL the index keeps the plan's digests, but the plan it would name is read again and is closed: %+v", got)
	}
	res := f.get(t, prefetchPath(f.ref, "node-a"), f.token, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("the route reads fresh and must refuse a closed plan at once, got %d", res.StatusCode)
	}
	now = now.Add(agentPrefetchIndexTTL)
	if got := f.config(t).AgentUpdate; got.Prefetch != nil || len(got.Keep) != 0 {
		t.Fatalf("past its TTL the index must be rebuilt: %+v", got)
	}
}

// When an approved plan's task is queued behind a newer pending plan, the
// approved one runs first and its script removes every other kept
// download, so that is the file to fetch; while it runs, nothing is.
func TestAgentPrefetchFetchesThePlanThatRunsNext(t *testing.T) {
	f := newPrefetchFixture(t, 16<<10, true)
	task := f.approveWithTask(t, false)
	payload, err := agentUpdatePayloadFromApproval(f.approval)
	if err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("a newer binary"))
	payload.SHA256 = hex.EncodeToString(other[:])
	newer := f.approval
	newer.ID, newer.Status, newer.CreatedAt = id.New("approval"), model.ApprovalPending, f.approval.CreatedAt.Add(time.Minute)
	newer.Action = agentUpdateApprovalAction(payload)
	if err := f.st.UpsertApproval(newer); err != nil {
		t.Fatal(err)
	}
	got := f.config(t).AgentUpdate
	if got.Prefetch == nil || got.Prefetch.ApprovalID != f.approval.ID {
		t.Fatalf("the queued approved plan must be fetched, got %+v", got.Prefetch)
	}
	if !slices.Contains(got.Keep, payload.SHA256) || !slices.Contains(got.Keep, f.ref.GzipSHA256) {
		t.Fatalf("keep must name both open plans: %v", got.Keep)
	}
	if _, err := f.st.LeaseTasks("node-a", 1); err != nil {
		t.Fatal(err)
	}
	if queued, leased := f.st.ApprovalTaskState(f.approval.ID); queued || !leased {
		t.Fatalf("task %s must be leased now", task.ID)
	}
	f.srv.now = func() time.Time { return time.Now().Add(agentPrefetchIndexTTL) }
	if got := f.config(t).AgentUpdate; got.Prefetch != nil {
		t.Fatalf("nothing is fetched while an update runs: %+v", got.Prefetch)
	}

	// A newer approved plan with its task queued behind the running one is
	// not fetched either: the running script would remove its file, and the
	// agent it restarts would not be held.
	newer.Status = model.ApprovalApproved
	if err := f.st.UpsertApproval(newer); err != nil {
		t.Fatal(err)
	}
	if err := f.st.CreateTask(model.Task{
		ID: id.New("task"), ApprovalID: newer.ID, Targets: []string{"node-a"},
		Interpreter: "sh", Script: "true", TimeoutSec: 600, OutputLimit: 65536,
		Status: model.TaskQueued, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	f.srv.now = func() time.Time { return time.Now().Add(2 * agentPrefetchIndexTTL) }
	if got := f.config(t).AgentUpdate; got.Prefetch != nil {
		t.Fatalf("a leased update anywhere among the open plans stops prefetch: %+v", got.Prefetch)
	}
}

// A node that resumes, or asks for ranges as fast as the limiter allows,
// writes one serve audit a minute for its approval, with the folded count.
func TestAgentPrefetchServeAuditsAreFolded(t *testing.T) {
	f := newPrefetchFixture(t, 16<<10, true)
	now := time.Now()
	f.srv.now = func() time.Time { return now }
	serves := func() []model.AuditEvent {
		var out []model.AuditEvent
		for _, ev := range f.st.AuditEvents() {
			if ev.Action == "agent.binary.prefetch" && ev.Decision != "deny" {
				out = append(out, ev)
			}
		}
		return out
	}
	for range 3 {
		res := f.get(t, prefetchPath(f.ref, "node-a"), f.token, map[string]string{"Range": "bytes=0-0"})
		res.Body.Close()
		if res.StatusCode != http.StatusPartialContent {
			t.Fatalf("status %d", res.StatusCode)
		}
	}
	if got := serves(); len(got) != 1 {
		t.Fatalf("repeats inside a minute must fold into one audit, got %d", len(got))
	}
	now = now.Add(time.Minute)
	res := f.get(t, prefetchPath(f.ref, "node-a"), f.token, nil)
	res.Body.Close()
	// The store lists audit events newest first.
	got := serves()
	if len(got) != 2 || got[0].Metadata["suppressed_repeats"] != "2" || got[0].Metadata["range"] != "" {
		t.Fatalf("the next audit must carry the folded count: %d events, %v", len(got), got[0].Metadata)
	}
}

// The node's report is shown beside the approval it is for, bounded and
// cleaned, and only while it is current.
func TestAgentPrefetchReportIsShownBesideItsApproval(t *testing.T) {
	f := newPrefetchFixture(t, 16<<10, true)
	cookies, _ := loginSession(t, f.handler)
	beat := func(prefetch string) {
		t.Helper()
		body := `{"node_id":"node-a","version":"0.1.0","metrics":{}` + prefetch + `}`
		if rec := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/metrics", body, f.token); rec.Code != http.StatusOK {
			t.Fatalf("beat: %d %s", rec.Code, rec.Body.String())
		}
	}
	shown := func() *agentPrefetchView {
		t.Helper()
		rec := authedGet(t, f.handler, cookies, "/api/network/approvals")
		if rec.Code != http.StatusOK {
			t.Fatalf("approvals: %d", rec.Code)
		}
		var rows []struct {
			ID       string             `json:"id"`
			Prefetch *agentPrefetchView `json:"prefetch"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ID == f.approval.ID {
				return row.Prefetch
			}
		}
		t.Fatal("the approval is not listed")
		return nil
	}
	report := func(state, reason string, bytes int, approvalID string) string {
		raw, err := json.Marshal(agentPrefetchFacts{
			ApprovalID: approvalID, SHA256: f.ref.GzipSHA256, Bytes: int64(bytes), Size: int64(len(f.served)),
			State: state, Reason: reason,
		})
		if err != nil {
			t.Fatal(err)
		}
		return `,"prefetch":` + string(raw)
	}

	if shown() != nil {
		t.Fatal("nothing is shown before the node reports")
	}
	beat(report("fetching", "\x1b[31mresuming\nafter a cut", 4096, f.approval.ID))
	got := shown()
	if got == nil || got.State != "fetching" || got.Bytes != 4096 || got.Size != int64(len(f.served)) || got.Reason != "[31mresumingafter a cut" {
		t.Fatalf("shown %+v", got)
	}
	byID := authedGet(t, f.handler, cookies, "/api/network/approvals?id="+f.approval.ID)
	if !strings.Contains(byID.Body.String(), `"prefetch":{"state":"fetching"`) {
		t.Fatalf("the read by id must show it too: %s", byID.Body.String())
	}

	beat(report("exploded", "", 1, f.approval.ID))
	beat(report("fetching", "", len(f.served)+1, f.approval.ID))
	if got := shown(); got == nil || got.Bytes != 4096 {
		t.Fatalf("a report outside the agent's shape must be dropped and leave the last one: %+v", got)
	}
	beat(report("complete", "", len(f.served), "approval-other"))
	if got := shown(); got != nil {
		t.Fatalf("a report for another approval must not be shown here: %+v", got)
	}
	other, err := json.Marshal(agentPrefetchFacts{ApprovalID: f.approval.ID, SHA256: f.ref.SHA256, Bytes: 1, Size: int64(len(f.served)), State: "complete"})
	if err != nil {
		t.Fatal(err)
	}
	beat(`,"prefetch":` + string(other))
	if got := shown(); got != nil {
		t.Fatalf("a report naming a file the approval does not pin must not be shown: %+v", got)
	}
	beat(report("complete", "", len(f.served), f.approval.ID))
	if got := shown(); got == nil || got.State != "complete" {
		t.Fatalf("shown %+v", got)
	}
	f.srv.now = func() time.Time { return time.Now().Add(agentPrefetchReportTTL + time.Minute) }
	if got := shown(); got != nil {
		t.Fatalf("a report older than its TTL must not be shown: %+v", got)
	}
	f.srv.now = time.Now
	beat("")
	if got := shown(); got != nil {
		t.Fatalf("a beat without a report must clear it: %+v", got)
	}
}

// End to end: a node whose line cannot carry the file inside one task's
// budget fetches most of it through the prefetch route beforehand, resuming
// once, and the approved task then continues that very file and installs
// inside the budget. The same task without the prefetch fails.
func TestAgentPrefetchedFileLetsTheTaskFinishInsideTheBudget(t *testing.T) {
	f := newPrefetchFixture(t, 384<<10, true)
	const rate, budget = 8 << 10, 6
	// From zero the walk can move at most rate*budget bytes.
	if len(f.served) < 2*rate*budget {
		t.Fatalf("the fixture must be too large to fetch from zero inside the budget: %d bytes", len(f.served))
	}
	path := prefetchPath(f.ref, "node-a")
	etag := `"` + f.ref.GzipSHA256 + `"`

	// The prefetch, as the agent makes it: a first response cut short, then
	// a resume from where the file ends, and the hand-off taking the file
	// before its last 4 KiB arrived.
	res := f.get(t, path, f.token, nil)
	first, _ := io.ReadAll(res.Body)
	res.Body.Close()
	prefetched := append([]byte(nil), first[:len(first)/3]...)
	res = f.get(t, path, f.token, map[string]string{"Range": fmt.Sprintf("bytes=%d-", len(prefetched)), "If-Range": etag})
	rest, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusPartialContent {
		t.Fatalf("resume: %d", res.StatusCode)
	}
	prefetched = append(prefetched, rest...)
	prefetched = prefetched[:len(prefetched)-4096]
	if string(prefetched) != string(f.served[:len(prefetched)]) {
		t.Fatal("the prefetched bytes must be a prefix of the served object")
	}

	task := f.approveWithTask(t, true)
	script, _ := walkScript(t, f.approval, nil)
	overrides := realWalkOverrides(budget)
	run := func(t *testing.T, kept map[string][]byte) (walkOutcome, *walkServer) {
		t.Helper()
		cp := newWalkServer(t, f.handler, walkBehaviour{rate: rate})
		fb := newWalkServer(t, serveBytes(f.data), walkBehaviour{status: http.StatusNotFound})
		o := runWalkScript(t, script, walkRun{
			fetcher: "curl", real: true, clock: "host", caFile: walkCAFile(t, cp),
			cpURL: cp.URL + f.ref.urlPath(), fbURL: fb.URL + "/lattice-agent-linux-amd64",
			overrides: overrides, kept: kept,
			env: []string{"LATTICE_TASK_ID=" + task.ID, "LATTICE_TASK_LEASE_ID=" + task.LeaseID},
		})
		return o, cp
	}
	t.Run("without the prefetch", func(t *testing.T) {
		o, _ := run(t, nil)
		if o.exit == 0 || o.installed != nil {
			t.Fatalf("the throttled line must not carry the whole file inside %d s: exit %d", budget, o.exit)
		}
	})
	t.Run("with the prefetched file", func(t *testing.T) {
		packedName := agentUpdatePartialPrefix + f.ref.GzipSHA256
		o, cp := run(t, map[string][]byte{packedName: prefetched})
		if o.exit != 0 || string(o.installed) != string(f.data) {
			t.Fatalf("exit %d, stderr:\n%s", o.exit, o.stderr)
		}
		seen := cp.requests()
		if len(seen) != 1 || seen[0].Get("Range") != fmt.Sprintf("bytes=%d-", len(prefetched)) || seen[0].Get(agentTaskLeaseHeader) != task.LeaseID {
			t.Fatalf("the task must continue the prefetched file: %v", seen)
		}
		if want := fmt.Sprintf("1:cp.gz:0:%d:", len(f.served)-len(prefetched)); !strings.Contains(o.summary, want) {
			t.Fatalf("summary %q, want %q", o.summary, want)
		}
		if _, ok := o.kept(packedName); ok {
			t.Fatal("the installed download must be removed")
		}
	})
}

// The names lattice-node-agent's prefetch shares with the apply script and
// this route. The agent pins the same literals
// (TestPrefetchContractNamesMatchTheServer in internal/prefetch), so a change
// on one side fails a test until the other follows.
func TestAgentPrefetchContractNamesMatchTheAgent(t *testing.T) {
	for got, want := range map[string]string{
		agentUpdatePartialPrefix:        ".lattice-agent-download-",
		defaultAgentInstallPath:         "/opt/lattice/node-agent/lattice-agent",
		previousDefaultAgentInstallPath: "/opt/lattice/lattice-agent",
		legacyAgentInstallPath:          "/usr/local/bin/lattice-agent",
		agentPrefetchPathPrefix:         "/api/agent/prefetch-binary/",
	} {
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
}
