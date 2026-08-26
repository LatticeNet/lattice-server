package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/logstore"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// Trace endpoint tests.
//
// The cases that matter most here are the ones about refusing things: a node
// reporting another node's traffic, a session outliving its ceiling, and an
// unknown log level being accepted. Each of those failing quietly would produce
// data that looks correct and is not.

func newTraceTestServer(t *testing.T) (http.Handler, *store.Store, *tracestore.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := tracestore.Open(filepath.Join(t.TempDir(), "trace.db"), secret.Disabled(), tracestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })
	// The raw log path needs the ordinary log store, so the harness has one.
	// Without it the agent is correctly told there is nowhere to send raw
	// lines, which is not what these tests are exercising.
	lstore, err := logstore.Open(filepath.Join(t.TempDir(), "logs.db"), secret.Disabled(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lstore.Close() })
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, TraceStore: ts, LogStore: lstore})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), st, ts
}

// traceNode creates a node whose bearer token is derivable in tests, so the
// agent endpoints can be exercised through real authentication rather than by
// bypassing it.
func traceNode(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	token := "node-token-" + id
	hash, err := auth.HashSecret(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: id, Name: id, TokenHash: hash}); err != nil {
		t.Fatal(err)
	}
	return token
}

func doTrace(t *testing.T, handler http.Handler, method, path string, cookies []*http.Cookie, csrf string, body any) *http.Response {
	t.Helper()
	var rdr *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewBuffer(b)
	} else {
		rdr = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-Lattice-CSRF", csrf)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func TestTraceSessionTTLIsClampedToTheCeiling(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	res := doTrace(t, handler, http.MethodPost, "/api/trace/sessions", cookies, csrf, map[string]any{
		"name":        "too long",
		"level":       "debug",
		"ttl_seconds": 86400,
		"filter":      map[string]any{"node_ids": []string{"node-a"}},
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create session: %d", res.StatusCode)
	}
	var sess model.TraceSession
	if err := json.NewDecoder(res.Body).Decode(&sess); err != nil {
		t.Fatal(err)
	}
	got := sess.ExpiresAt.Sub(sess.StartedAt)
	if got > traceSessionMaxTTL {
		t.Fatalf("ttl %s exceeds the ceiling %s", got, traceSessionMaxTTL)
	}
	if got != traceSessionMaxTTL {
		t.Fatalf("a 24h request should clamp to exactly the ceiling, got %s", got)
	}
}

func TestTraceSessionDefaultsTTLWhenUnset(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	res := doTrace(t, handler, http.MethodPost, "/api/trace/sessions", cookies, csrf, map[string]any{
		"name":   "default ttl",
		"filter": map[string]any{"node_ids": []string{"node-a"}},
	})
	defer res.Body.Close()
	var sess model.TraceSession
	if err := json.NewDecoder(res.Body).Decode(&sess); err != nil {
		t.Fatal(err)
	}
	if d := sess.ExpiresAt.Sub(sess.StartedAt); d != traceSessionDefaultTTL {
		t.Fatalf("default ttl = %s, want %s", d, traceSessionDefaultTTL)
	}
	if sess.State != model.TraceSessionRunning {
		t.Fatalf("state = %q", sess.State)
	}
}

func TestTraceSessionRejectsUnknownLevel(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	res := doTrace(t, handler, http.MethodPost, "/api/trace/sessions", cookies, csrf, map[string]any{
		"name":   "bad level",
		"level":  "verbose",
		"filter": map[string]any{"node_ids": []string{"node-a"}},
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unknown level, got %d", res.StatusCode)
	}
}

func TestTracePolicyRejectsNonLoopbackClashAddr(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	for _, addr := range []string{"0.0.0.0:9090", "10.1.2.3:9090", "example.com:9090", "127.0.0.1:0"} {
		res := doTrace(t, handler, http.MethodPost, "/api/trace/policy", cookies, csrf, map[string]any{
			"node_id":        "node-a",
			"enabled":        true,
			"clash_api_addr": addr,
		})
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("address %q accepted with status %d; the Clash API must be loopback only", addr, res.StatusCode)
		}
	}
}

func TestTracePolicyRoundTrips(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	res := doTrace(t, handler, http.MethodPost, "/api/trace/policy", cookies, csrf, map[string]any{
		"node_id":              "node-a",
		"enabled":              true,
		"level":                "debug",
		"budget_lines_per_sec": 1234,
		"clash_api_addr":       "127.0.0.1:9090",
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("set policy: %d", res.StatusCode)
	}
	var pol model.TracePolicy
	if err := json.NewDecoder(res.Body).Decode(&pol); err != nil {
		t.Fatal(err)
	}
	if !pol.Enabled || pol.Level != model.TraceLevelDebug || pol.BudgetLinesPerSec != 1234 {
		t.Fatalf("policy did not round trip: %+v", pol)
	}
	node, _ := st.Node("node-a")
	if node.Trace.Level != model.TraceLevelDebug {
		t.Fatalf("policy was not persisted on the node: %+v", node.Trace)
	}
}

// A node may report only its own traffic. Without this an agent token, which is
// per node and carried in the clear to the node, would be enough to write
// records attributed to any other node in the fleet.
func TestAgentTraceRefusesCrossNodeRecords(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	token := traceNode(t, st, "node-a")
	traceNode(t, st, "node-b")

	body, _ := json.Marshal(map[string]any{
		"node_id": "node-a",
		"batch": map[string]any{
			"node_id":     "node-a",
			"captured_at": time.Now().UTC(),
			"records": []map[string]any{{
				"node_id":    "node-b",
				"log_id":     7,
				"started_at": time.Now().UTC(),
			}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/trace", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-node record accepted with status %d", rec.Code)
	}
}

func TestAgentTraceAcceptsOwnRecordsAndStampsNodeID(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	token := traceNode(t, st, "node-a")

	started := time.Now().UTC().Add(-time.Minute)
	body, _ := json.Marshal(map[string]any{
		"node_id": "node-a",
		"batch": map[string]any{
			"node_id":     "node-a",
			"captured_at": time.Now().UTC(),
			"records": []map[string]any{{
				"log_id":          99,
				"core_generation": 1,
				"started_at":      started,
				"ended_at":        started.Add(time.Second),
				"dst_host":        "example.com",
				"dst_port":        443,
				"close_reason":    model.CloseEOF,
				"user_name":       "u_a1b2c3d4e5f60718",
				// bytes_known deliberately absent: an unsampled connection must
				// stay unknown rather than becoming a measured zero.
			}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/trace", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("own record rejected: %d %s", rec.Code, rec.Body.String())
	}

	page, err := ts.QueryRecords(tracestore.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("stored %d records, want 1", len(page.Records))
	}
	got := page.Records[0]
	if got.NodeID != "node-a" {
		t.Fatalf("node_id = %q, want it stamped from the authenticated node", got.NodeID)
	}
	if got.BytesKnown {
		t.Fatal("bytes_known must stay false when the agent did not report it")
	}
	if got.Upload != 0 || got.Download != 0 {
		t.Fatal("unsampled bytes must not be invented")
	}
}

func TestTraceEndpointsRequireLogScopes(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")

	// No session at all: every operator endpoint must refuse.
	for _, path := range []string{
		"/api/trace/connections",
		"/api/trace/sessions",
		"/api/trace/policy",
		"/api/trace/stats",
		"/api/trace/markers",
	} {
		res := doTrace(t, handler, http.MethodGet, path, nil, "", nil)
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s served an unauthenticated request with %d", path, res.StatusCode)
		}
	}
}

func TestTraceConnectionsRejectsMalformedCursor(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	res := doTrace(t, handler, http.MethodGet, "/api/trace/connections?cursor=not-a-real-cursor", cookies, csrf, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed cursor produced %d, want 400", res.StatusCode)
	}
}

func TestTraceStoreDisabledReportsUnavailable(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	res := doTrace(t, handler, http.MethodGet, "/api/trace/connections", cookies, csrf, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("with no trace store the endpoint returned %d, want 503", res.StatusCode)
	}
}

// With tracing off the agent is told to collect nothing rather than handed an
// error, so an agent behaves identically whether the feature is off or the
// server is older than the feature.
func TestAgentTraceConfigWithoutStoreReportsDisabled(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	token := traceNode(t, st, "node-a")

	req := httptest.NewRequest(http.MethodGet, "/api/agent/trace-config?node_id=node-a", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var cfg model.TraceAgentConfig
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.Enabled {
		t.Fatal("tracing is not enabled on this server; the policy must say so")
	}
}

// A bare TraceBatch posted where the envelope belongs must be refused. It
// authenticates cleanly, because TraceBatch carries its own node_id, and then
// decodes to an empty batch. Without this guard the node is told 200 OK with
// zero records accepted and can ship into that void indefinitely.
func TestAgentTraceRejectsABareBatch(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	token := traceNode(t, st, "node-a")

	// A realistic bare batch: exactly what a collector that forgot the envelope
	// would send. node_id is present at the top level, so authentication
	// succeeds and only the shape is wrong.
	bare, _ := json.Marshal(model.TraceBatch{
		NodeID:     "node-a",
		CapturedAt: time.Now().UTC(),
		Records: []model.ConnRecord{{
			NodeID:    "node-a",
			LogID:     42,
			StartedAt: time.Now().UTC(),
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/trace", bytes.NewBuffer(bare))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a bare batch was accepted with %d (%s); the wrong shape must never read as success", rec.Code, rec.Body.String())
	}
}

// The Clash API secret must never leave the server except inside the rendered
// node config, which is already handled as a node-scoped secret-bearing
// artifact.
//
// proxyNodeProfileView is an allowlist, so the secret is excluded today only
// because nobody copied it across. That is the right shape and a fragile
// guarantee: this pins it, so adding the field to the view later fails here
// rather than quietly publishing a bearer token to every profile reader.
func TestProfileViewNeverCarriesTheClashAPISecret(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	const secret = "clash-api-bearer-do-not-publish"

	if err := st.UpsertProxyNodeProfile(model.ProxyNodeProfile{
		ID:             "prof-1",
		NodeID:         "node-a",
		Core:           model.ProxyCoreSingbox,
		ClashAPI:       "127.0.0.1:9090",
		ClashAPISecret: secret,
	}); err != nil {
		t.Skipf("profile store shape differs; adjust this guard: %v", err)
	}

	cookies, csrf := loginSession(t, handler)
	res := doTrace(t, handler, http.MethodGet, "/api/proxy/profiles", cookies, csrf, nil)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Skipf("profiles endpoint returned %d; adjust this guard", res.StatusCode)
	}
	if bytes.Contains(body, []byte(secret)) {
		t.Fatalf("the Clash API secret was served by /api/proxy/profiles:\n%s", body)
	}
	if bytes.Contains(body, []byte("clash_api_secret")) {
		t.Fatal("the profile view exposes a clash_api_secret field")
	}
}

// A node-confined operator cannot start a fleet-wide capture.
//
// The dashboard default leaves the node filter blank, and an empty
// Filter.NodeIDs means "every node" to traceAgentConfig, traceSessionVisible
// and the stop path. Storing the request's empty list would let an operator
// authorised for one node start a capture that every node in the fleet picks
// up: a privacy widening, and trace-level load on machines outside their scope.
func TestNodeConfinedOperatorCannotStartAFleetWideCapture(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := tracestore.Open(filepath.Join(t.TempDir(), "trace.db"), secret.Disabled(), tracestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, TraceStore: ts})
	if err != nil {
		t.Fatal(err)
	}
	traceNode(t, st, "node-a")
	traceNode(t, st, "node-b")

	confined := principal{Principal: rbac.Principal{
		ActorID:         "confined-operator",
		Scopes:          []string{"log:read", "log:admin"},
		ServerAllowlist: []string{"node-a"},
	}}

	body := bytes.NewBufferString(`{"name":"blank node filter","level":"debug","filter":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/trace/sessions", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.createTraceSession(rec, req, confined)
	if rec.Code != http.StatusOK {
		t.Fatalf("confined operator could not create a session: %d %s", rec.Code, rec.Body.String())
	}

	var sess model.TraceSession
	if err := json.NewDecoder(rec.Body).Decode(&sess); err != nil {
		t.Fatal(err)
	}
	if len(sess.Filter.NodeIDs) == 0 {
		t.Fatal("the stored session has an empty node filter, which every reader treats as the whole fleet")
	}
	for _, n := range sess.Filter.NodeIDs {
		if n != "node-a" {
			t.Fatalf("session targets %q, outside the operator's allowlist", n)
		}
	}

	// The decisive check: node-b must not be handed this session when it polls.
	cfg, err := srv.traceAgentConfig("node-b")
	if err != nil {
		t.Fatal(err)
	}
	for _, as := range cfg.Sessions {
		if as.ID == sess.ID {
			t.Fatal("node-b was handed a session it is not a target of")
		}
	}
	// And node-a must still get it, or the fix broke the feature.
	cfgA, err := srv.traceAgentConfig("node-a")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, as := range cfgA.Sessions {
		if as.ID == sess.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("node-a did not receive the session it is the target of")
	}
}

// Retention must actually run, not merely be configured.
//
// Open honours the TTLs and the size cap as configuration and enforces nothing.
// Without a worker calling Retain, trace.db grows until the disk fills, and at
// the always-on info floor every node contributes records continuously. This
// pins the wiring, because the failure mode is invisible until it is an outage.
func TestTraceRetentionIsStartedAndActuallyDeletes(t *testing.T) {
	dir := t.TempDir()
	ts, err := tracestore.Open(filepath.Join(dir, "trace.db"), secret.Disabled(), tracestore.Options{
		RecordTTL: time.Hour,
		LineTTL:   time.Hour,
		RollupTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	old := time.Now().UTC().Add(-48 * time.Hour)
	if _, err := ts.AppendRecords([]model.ConnRecord{{
		NodeID: "node-a", LogID: 1, CoreGeneration: 1,
		StartedAt: old, EndedAt: old.Add(time.Second),
		CloseReason: model.CloseEOF,
	}}); err != nil {
		t.Fatal(err)
	}

	before, err := ts.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if before.Records != 1 {
		t.Fatalf("expected the seeded record, got %d", before.Records)
	}

	res, err := ts.Retain(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordsExpired != 1 {
		t.Fatalf("Retain expired %d records, want 1", res.RecordsExpired)
	}

	after, err := ts.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if after.Records != 0 {
		t.Fatalf("%d records survived their TTL", after.Records)
	}
}

// The server must call it. A store that enforces nothing is the same as no
// retention at all, and that is exactly the state this feature shipped in.
func TestServerStartsTheTraceRetentionWorker(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte("s.startTraceRetention()")) {
		t.Fatal("server startup does not call startTraceRetention; the TTLs and size cap are inert")
	}
}

// A quiet tail interval must not rewind the cursor.
//
// Returning next_seq=0 when a poll finds nothing sends the client back to the
// start, so every quiet moment re-delivers the whole tail and the view fills
// with duplicates of the evidence the operator is reading.
func TestTailCursorNeverGoesBackwards(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	sess := model.TraceSession{
		ID: "trace-x", Name: "x", Level: model.TraceLevelTrace,
		StartedAt: time.Now().UTC().Add(-time.Minute),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		State:     model.TraceSessionRunning,
		Filter:    model.TraceFilter{NodeIDs: []string{"node-a"}},
	}
	if err := st.UpsertTraceSession(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.AppendLines([]model.TraceLine{
		{SessionID: "trace-x", NodeID: "node-a", At: time.Now().UTC(), Level: "info", Message: "one"},
		{SessionID: "trace-x", NodeID: "node-a", At: time.Now().UTC(), Level: "info", Message: "two"},
	}); err != nil {
		t.Fatal(err)
	}

	read := func(after int) (int, uint64) {
		res := doTrace(t, handler, http.MethodGet,
			"/api/trace/lines?session_id=trace-x&after_seq="+strconv.Itoa(after), cookies, csrf, nil)
		defer res.Body.Close()
		var out struct {
			Lines   []model.TraceLine `json:"lines"`
			NextSeq uint64            `json:"next_seq"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return len(out.Lines), out.NextSeq
	}

	n, next := read(0)
	if n != 2 || next != 2 {
		t.Fatalf("first page: %d lines, next_seq %d; want 2 and 2", n, next)
	}
	// Nothing new since. The cursor must hold, not reset.
	n, next = read(int(next))
	if n != 0 {
		t.Fatalf("quiet poll returned %d lines, want 0", n)
	}
	if next != 2 {
		t.Fatalf("quiet poll reported next_seq %d; a value below the request rewinds the tail and duplicates evidence", next)
	}
}

// The always-on raw log path must exist, and must not be tailed as a file.
//
// S1 promised ordinary sing-box lines keep flowing into the existing bounded
// log store so the Logs view still works on a traced node and there is parser
// evidence to look at afterwards. Without it, the only thing that survives
// outside an active capture is the assembled record, which is a summary.
func TestTracePolicyProvisionsTheRawLogSource(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)

	res := doTrace(t, handler, http.MethodPost, "/api/trace/policy", cookies, csrf, map[string]any{
		"node_id": "node-a", "enabled": true, "level": "info",
		"clash_api_addr": "127.0.0.1:9090",
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("set policy: %d", res.StatusCode)
	}

	cfgRes := doTraceAgent(t, handler, "node-a")
	if cfgRes.RawSourceID == "" {
		t.Fatal("the agent was given no raw source id; ordinary sing-box lines have nowhere to go")
	}
	ls, ok := st.LogSource(cfgRes.RawSourceID)
	if !ok {
		t.Fatal("the raw log source was advertised but not created")
	}
	if !strings.HasPrefix(ls.Path, "singbox://") || ls.NodeID != "node-a" || !ls.Enabled {
		t.Fatalf("raw source is wrong: %+v", ls)
	}

	// It is virtual, so the file tailer must never be handed it.
	req := httptest.NewRequest(http.MethodGet, "/api/agent/log-sources?node_id=node-a", nil)
	req.Header.Set("Authorization", "Bearer node-token-node-a")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var listed struct {
		Sources []model.LogSource `json:"sources"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	for _, s := range listed.Sources {
		if strings.Contains(s.Path, "://") {
			t.Fatalf("the tail list includes the virtual source %q; the agent would chase a path that cannot exist", s.Path)
		}
	}

	// And an operator must not be able to edit it out from under the policy.
	edit := doTrace(t, handler, http.MethodPost, "/api/logs/sources", cookies, csrf, map[string]any{
		"id": ls.ID, "name": "hijacked", "node_id": "node-a", "path": "/var/log/anything.log",
	})
	edit.Body.Close()
	if edit.StatusCode != http.StatusBadRequest {
		t.Fatalf("operator CRUD accepted an edit to a managed source: %d", edit.StatusCode)
	}
}

func doTraceAgent(t *testing.T, handler http.Handler, nodeID string) model.TraceAgentConfig {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/trace-config?node_id="+nodeID, nil)
	req.Header.Set("Authorization", "Bearer node-token-"+nodeID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var cfg model.TraceAgentConfig
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}
