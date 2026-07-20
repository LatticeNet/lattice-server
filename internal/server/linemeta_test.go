package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newLinemetaTestServer(t *testing.T, st *store.Store) *Server {
	t.Helper()
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// (a) Allocation is idempotent per line_hash_id and survives a store reopen.
func TestEnsureLineUUIDIdempotentAndPersistent(t *testing.T) {
	dir := t.TempDir()
	stPath := filepath.Join(dir, "state.json")
	st, err := store.Open(stPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)

	const hash = "line_0123456789abcdef01234567"
	u1, err := srv.ensureLineUUID(hash)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	u2, err := srv.ensureLineUUID(hash)
	if err != nil {
		t.Fatalf("ensure again: %v", err)
	}
	if u1 != u2 {
		t.Fatalf("not idempotent: %q vs %q", u1, u2)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := store.Open(stPath)
	if err != nil {
		t.Fatal(err)
	}
	srv2 := newLinemetaTestServer(t, st2)
	u3, err := srv2.ensureLineUUID(hash)
	if err != nil {
		t.Fatalf("ensure after reopen: %v", err)
	}
	if u3 != u1 {
		t.Fatalf("uuid not persisted across reopen: %q vs %q", u3, u1)
	}
	if _, err := srv2.ensureLineUUID("  "); err == nil {
		t.Fatal("empty line_hash_id: want error")
	}
}

// (b) Allocated ids are well-formed UUIDv4 (36 chars, hyphen layout, version and
// variant bits) using the shared stdlib generator — no third-party dep.
func TestEnsureLineUUIDFormatV4(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	u, err := srv.ensureLineUUID("line_abcdef0123456789abcdef01")
	if err != nil {
		t.Fatal(err)
	}
	if len(u) != 36 {
		t.Fatalf("len = %d, want 36: %q", len(u), u)
	}
	for _, pos := range []int{8, 13, 18, 23} {
		if u[pos] != '-' {
			t.Fatalf("missing hyphen at %d: %q", pos, u)
		}
	}
	if u[14] != '4' {
		t.Fatalf("version nibble = %c, want 4: %q", u[14], u)
	}
	if c := u[19]; c != '8' && c != '9' && c != 'a' && c != 'b' {
		t.Fatalf("variant nibble = %c, want 8/9/a/b: %q", c, u)
	}
	if !proxyUUIDRe.MatchString(u) {
		t.Fatalf("proxyUUIDRe rejects %q", u)
	}
}

// seedLinemetaNodes sets up node-a (with a discovered hub line carrying a declared
// downstream_line_uuid, a relay line with no resolvable downstream, and a direct
// line) plus node-b hosting the hub's downstream endpoint.
func seedLinemetaNodes(t *testing.T, srv *Server) {
	t.Helper()
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "node-uuid-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertNode(model.Node{ID: "node-b", Name: "Node B", PublicIP: "198.51.100.9"}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {
			NodeID: "node-a", At: srv.now(), Status: "ok",
			Nodes: []model.SingBoxNode{
				{Name: "hub-a", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443", OutboundRef: "exit-b", OutboundServer: "198.51.100.9", OutboundPort: "8443", DownstreamLineUUID: "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e"},
				{Name: "orphan-relay", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "8080", OutboundRef: "relay-x", OutboundServer: "10.0.0.1", OutboundPort: "9999"},
				{Name: "direct-a", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "80", OutboundRef: "direct"},
			},
		},
		"node-b": {
			NodeID: "node-b", At: srv.now(), Status: "ok",
			Nodes: []model.SingBoxNode{
				{Name: "exit-b-in", Protocol: "vless", Network: "tcp", Address: "198.51.100.9", Port: "8443"},
			},
		},
	}
	srv.singboxInvMu.Unlock()
}

func findLine(t *testing.T, groups []LineGroup, nodeID, tag string) Line {
	t.Helper()
	for _, g := range groups {
		if g.NodeID != nodeID {
			continue
		}
		for _, ln := range g.Lines {
			if ln.Tag == tag {
				return ln
			}
		}
	}
	t.Fatalf("line %s/%s not found: %+v", nodeID, tag, groups)
	return Line{}
}

// (c) buildLineGroups fills line_uuid on every line (persisted, stable across
// calls) and passes discovered downstream_line_uuid through.
func TestBuildLineGroupsFillsLineUUIDs(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	groups := srv.buildLineGroups()
	hub := findLine(t, groups, "node-a", "hub-a")
	direct := findLine(t, groups, "node-a", "direct-a")
	exit := findLine(t, groups, "node-b", "exit-b-in")
	for _, ln := range []Line{hub, direct, exit} {
		if !proxyUUIDRe.MatchString(ln.LineUUID) {
			t.Fatalf("line %s: line_uuid unset/invalid: %+v", ln.Tag, ln)
		}
	}
	if hub.LineUUID == direct.LineUUID || hub.LineUUID == exit.LineUUID || direct.LineUUID == exit.LineUUID {
		t.Fatalf("line_uuids must be distinct: %q %q %q", hub.LineUUID, direct.LineUUID, exit.LineUUID)
	}
	if hub.DownstreamLineUUID != "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e" {
		t.Fatalf("discovered downstream_line_uuid not passed through: %+v", hub)
	}
	if direct.DownstreamLineUUID != "" || exit.DownstreamLineUUID != "" {
		t.Fatalf("lines without a declared downstream must stay empty: %+v %+v", direct, exit)
	}
	// Persisted mapping matches the read model; re-build keeps the same uuid.
	e, ok := srv.store.KVEntry(lineUUIDKVBucket, hub.LineHashID)
	if !ok || e.Value != hub.LineUUID {
		t.Fatalf("kv mapping mismatch: %+v ok=%v want %q", e, ok, hub.LineUUID)
	}
	if again := findLine(t, srv.buildLineGroups(), "node-a", "hub-a"); again.LineUUID != hub.LineUUID {
		t.Fatalf("line_uuid not stable across rebuilds: %q vs %q", again.LineUUID, hub.LineUUID)
	}
}

// (c2) A declared downstream_line_uuid resolves to the downstream line's hash
// fleet-wide (design-15 §6): the hub gains a declared jump edge, and provenance
// is kept separate from inferred edges. Unknown/self uuids resolve to nothing.
func TestBuildLineGroupsDeclaredEdges(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	// Pre-seed the downstream's mapping so its allocated uuid equals the hub's
	// declared downstream_line_uuid (hub-a -> exit-b-in).
	exitHash := findLine(t, srv.buildLineGroups(), "node-b", "exit-b-in").LineHashID
	if err := srv.store.PutKV(model.KVEntry{Bucket: lineUUIDKVBucket, Key: exitHash, Value: "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e"}); err != nil {
		t.Fatal(err)
	}
	hub := findLine(t, srv.buildLineGroups(), "node-a", "hub-a")
	if !containsString(hub.JumpEdges, exitHash) {
		t.Fatalf("declared edge missing from jump_edges: %+v", hub)
	}
	if !containsString(hub.DeclaredJumpEdges, exitHash) {
		t.Fatalf("declared edge missing from declared_jump_edges: %+v", hub)
	}
	// The inferred path already found hub-a -> exit-b via (host,port); the
	// declared resolution must not duplicate it.
	count := 0
	for _, edge := range hub.JumpEdges {
		if edge == exitHash {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("edge duplicated: %+v", hub.JumpEdges)
	}
	// A line without a resolvable downstream has no declared edges.
	orphan := findLine(t, srv.buildLineGroups(), "node-a", "orphan-relay")
	if len(orphan.DeclaredJumpEdges) != 0 {
		t.Fatalf("orphan must not gain declared edges: %+v", orphan)
	}
	// A declared uuid unknown to the fleet resolves to nothing.
	srv.singboxInvMu.Lock()
	inv := srv.singboxInv["node-a"]
	inv.Nodes[2].DownstreamLineUUID = "7c3d8e2f-5a4b-4c6d-9e0f-1a2b3c4d5e6f"
	srv.singboxInv["node-a"] = inv
	srv.singboxInvMu.Unlock()
	dangling := findLine(t, srv.buildLineGroups(), "node-a", "direct-a")
	if len(dangling.DeclaredJumpEdges) != 0 || len(dangling.JumpEdges) != 0 {
		t.Fatalf("unknown downstream uuid must resolve to no edge: %+v", dangling)
	}
}

// (d) The renderer emits the exact contract shape (mirrors fixtures/v2-valid-full.json).
func TestRenderLineMetadataJSON(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	srv.now = func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) }
	seedLinemetaNodes(t, srv)

	raw, err := srv.renderLineMetadataJSON("node-a")
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	// Top-level key set matches the fixture shape.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"schema", "node_id", "node_uuid", "updated_at", "writer", "inbounds", "reserved"} {
		if _, ok := top[key]; !ok {
			t.Fatalf("missing top-level key %q in %s", key, raw)
		}
	}

	var doc struct {
		Schema    string `json:"schema"`
		NodeID    string `json:"node_id"`
		NodeUUID  string `json:"node_uuid"`
		UpdatedAt string `json:"updated_at"`
		Writer    string `json:"writer"`
		Inbounds  []struct {
			Tag        string `json:"tag"`
			LineUUID   string `json:"line_uuid"`
			LineHashID string `json:"line_hash_id"`
			Chain      *struct {
				DownstreamLineUUID *string `json:"downstream_line_uuid"`
				DownstreamNode     string  `json:"downstream_node"`
			} `json:"chain"`
		} `json:"inbounds"`
		Reserved struct {
			InConfigKey string            `json:"in_config_key"`
			Fields      map[string]string `json:"fields"`
		} `json:"reserved"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("typed decode: %v", err)
	}
	if doc.Schema != "lattice.singbox-metadata.v2" || doc.Writer != "lattice-server" {
		t.Fatalf("schema/writer: %+v", doc)
	}
	if doc.NodeID != "node-a" || doc.NodeUUID != "node-uuid-a" {
		t.Fatalf("node identity: %+v", doc)
	}
	ts, err := time.Parse(time.RFC3339, doc.UpdatedAt)
	if err != nil || !ts.Equal(srv.now()) {
		t.Fatalf("updated_at %q: %v", doc.UpdatedAt, err)
	}
	if doc.Reserved.InConfigKey != "_lattice" ||
		doc.Reserved.Fields["line_uuid"] != "string" || doc.Reserved.Fields["node_uuid"] != "string" ||
		doc.Reserved.Fields["line_hash_id"] != "string" || len(doc.Reserved.Fields) != 3 {
		t.Fatalf("reserved block: %+v", doc.Reserved)
	}

	// Inbounds sorted by tag: direct-a < hub-a < orphan-relay.
	if len(doc.Inbounds) != 3 {
		t.Fatalf("want 3 inbounds, got %d: %s", len(doc.Inbounds), raw)
	}
	if doc.Inbounds[0].Tag != "direct-a" || doc.Inbounds[1].Tag != "hub-a" || doc.Inbounds[2].Tag != "orphan-relay" {
		t.Fatalf("inbounds not sorted by tag: %s", raw)
	}
	groups := srv.buildLineGroups()
	for _, ib := range doc.Inbounds {
		if !proxyUUIDRe.MatchString(ib.LineUUID) {
			t.Fatalf("inbound %s line_uuid invalid: %q", ib.Tag, ib.LineUUID)
		}
		if want := findLine(t, groups, "node-a", ib.Tag); ib.LineUUID != want.LineUUID || ib.LineHashID != want.LineHashID {
			t.Fatalf("inbound %s diverges from read model: %+v vs %+v", ib.Tag, ib, want)
		}
	}
	if doc.Inbounds[0].Chain != nil {
		t.Fatalf("direct line must omit chain: %s", raw)
	}
	hubChain := doc.Inbounds[1].Chain
	if hubChain == nil || hubChain.DownstreamLineUUID == nil ||
		*hubChain.DownstreamLineUUID != "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e" || hubChain.DownstreamNode != "Node B" {
		t.Fatalf("hub chain wrong: %s", raw)
	}
	orphanChain := doc.Inbounds[2].Chain
	if orphanChain == nil || orphanChain.DownstreamLineUUID != nil || orphanChain.DownstreamNode != "" {
		t.Fatalf("unresolved relay chain must carry explicit null uuid and no node: %s", raw)
	}
	// Explicit null, not a missing key, for the unresolved relay.
	var ibs []map[string]json.RawMessage
	if err := json.Unmarshal(top["inbounds"], &ibs); err != nil {
		t.Fatal(err)
	}
	var orphanChainKeys map[string]json.RawMessage
	if err := json.Unmarshal(ibs[2]["chain"], &orphanChainKeys); err != nil {
		t.Fatal(err)
	}
	if v, ok := orphanChainKeys["downstream_line_uuid"]; !ok || string(v) != "null" {
		t.Fatalf("downstream_line_uuid must be explicit null: %s", ibs[2]["chain"])
	}
	if _, ok := orphanChainKeys["downstream_node"]; ok {
		t.Fatalf("downstream_node must be omitted when unknown: %s", ibs[2]["chain"])
	}

	// Deterministic: a second render of unchanged state is byte-identical.
	raw2, err := srv.renderLineMetadataJSON("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(raw2) {
		t.Fatal("render not deterministic")
	}
	// Node-b renders its own single-inbound doc; unknown node errors.
	if _, err := srv.renderLineMetadataJSON("node-b"); err != nil {
		t.Fatalf("render node-b: %v", err)
	}
	if _, err := srv.renderLineMetadataJSON("node-missing"); err == nil {
		t.Fatal("unknown node: want error")
	}
}

// (e) A persistence failure degrades the read model (uuid left empty) instead of
// failing it; ensureLineUUID surfaces the error to direct callers.
func TestBuildLineGroupsDegradesWhenAllocationFails(t *testing.T) {
	dir := t.TempDir()
	stPath := filepath.Join(dir, "state.json")
	st, err := store.Open(stPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	// Break persistence: replace the state dir with a regular file so every
	// Save fails inside MkdirAll.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := srv.ensureLineUUID("line_deadbeef0123456789abcdef"); err == nil {
		t.Fatal("ensureLineUUID with broken store: want error")
	}
	groups := srv.buildLineGroups()
	hub := findLine(t, groups, "node-a", "hub-a")
	if hub.LineUUID != "" {
		t.Fatalf("degraded read model must leave line_uuid empty, got %q", hub.LineUUID)
	}
	if hub.Tag != "hub-a" || hub.DownstreamLineUUID == "" {
		t.Fatalf("read model must otherwise stay intact: %+v", hub)
	}
}

// The apply task helper renders the sidecar into a reviewed sh script (atomic
// tmp+mv, .bak backup, 0644) and shapes the task without queueing it.
func TestLineMetadataApplyTaskShape(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	task, err := srv.newLineMetadataApplyTask(principal{Principal: rbac.Principal{ActorID: "op-1"}}, "node-a")
	if err != nil {
		t.Fatalf("task: %v", err)
	}
	if len(task.Targets) != 1 || task.Targets[0] != "node-a" || task.Interpreter != "sh" ||
		task.Status != model.TaskQueued || task.ActorID != "op-1" {
		t.Fatalf("task shape: %+v", task)
	}
	for _, want := range []string{
		"set -e", "/etc/sing-box/lattice-metadata.json", ".lattice-new", ".bak",
		"chmod 0644", "mv -f \"$CANDIDATE\" \"$TARGET\"", "lattice.singbox-metadata.v2",
	} {
		if !strings.Contains(task.Script, want) {
			t.Fatalf("script missing %q:\n%s", want, task.Script)
		}
	}
	if _, err := srv.newLineMetadataApplyTask(principal{Principal: rbac.Principal{ActorID: "op-1"}}, "node-missing"); err == nil {
		t.Fatal("unknown node: want error")
	}
}
