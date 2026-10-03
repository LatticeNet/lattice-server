package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Production logged the regression refusal on every inventory post: seven
// hubs refused, one post per hub every ~10 s, 420 identical lines in 10
// minutes. The retry is the point (the next post may carry a warmer fleet
// view), so it stays; only the log line is held to once per change, once an
// hour while it persists, and once when the node queues again.
func TestLineMetaDiscoveryRefusalLogsOnceAnHourAndOnRecovery(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	now := time.Date(2026, 10, 3, 4, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	seedLinemetaNodes(t, srv)

	out, err := srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	var resp struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	applied := resp.Approval
	applied.Status = model.ApprovalApplied
	applied.UpdatedAt = now
	if err := st.UpsertApproval(applied); err != nil {
		t.Fatal(err)
	}

	// Restart: node-a posts before node-b, so every render loses the hub's
	// downstream_node and is refused.
	logs := &lockedLog{}
	srv.logger = log.New(logs, "", 0)
	now = now.Add(3 * time.Hour)
	srv.linemetaSyncFP = nil
	srv.singboxInvMu.Lock()
	invA := srv.singboxInv["node-a"]
	srv.singboxInv = map[string]model.SingBoxInventory{"node-a": invA}
	srv.singboxInvMu.Unlock()
	post := func() {
		t.Helper()
		srv.singboxInvMu.Lock()
		inv := srv.singboxInv["node-a"]
		inv.At = now
		srv.singboxInv["node-a"] = inv
		srv.singboxInvMu.Unlock()
		srv.invalidateLineReadModel()
		srv.maybeQueueLineMetaSyncOnDiscovery("node-a", inv)
	}
	refusals := func() []string { return logs.linesWith("would drop chain.downstream_node") }
	committed := func() bool {
		srv.linemetaSyncMu.Lock()
		defer srv.linemetaSyncMu.Unlock()
		_, ok := srv.linemetaSyncFP["node-a"]
		return ok
	}

	// Ten minutes of posts: 60 retries, one line.
	for i := 0; i < 60; i++ {
		post()
		now = now.Add(10 * time.Second)
	}
	if got := refusals(); len(got) != 1 {
		t.Fatalf("60 identical refusals logged %d lines, want 1: %q", len(got), got)
	}
	if !strings.HasPrefix(refusals()[0], "linemeta: queue sync for node-a: linemeta sync for node-a would drop chain.downstream_node on hub-a") {
		t.Fatalf("refusal line changed shape: %q", refusals()[0])
	}
	// Every post still retried and was refused; none committed a fingerprint.
	if committed() {
		t.Fatal("a refused sync committed its fingerprint, so the next post would not retry")
	}
	srv.linemetaSyncMu.Lock()
	quiet := srv.linemetaRefusals["node-a"].quiet
	srv.linemetaSyncMu.Unlock()
	if quiet != 59 {
		t.Fatalf("quiet refusals = %d, want 59", quiet)
	}

	// Still refused an hour after the line was logged: one reminder, counting
	// what it held back.
	now = now.Add(time.Hour)
	post()
	got := refusals()
	if len(got) != 2 || !strings.Contains(got[1], "(59 more since 2026-10-03T07:00:00Z)") {
		t.Fatalf("hourly reminder = %q", got)
	}
	now = now.Add(10 * time.Second)
	post()
	if n := len(refusals()); n != 2 {
		t.Fatalf("a post after the reminder logged again: %d lines", n)
	}

	// node-b posts; the warm render goes through. One line says so, and the
	// fingerprint commits, so the next identical post does nothing at all.
	srv.singboxInvMu.Lock()
	srv.singboxInv["node-b"] = model.SingBoxInventory{
		NodeID: "node-b", At: now, Status: "ok",
		Nodes: []model.SingBoxNode{
			{Name: "exit-b-in", Protocol: "vless", Network: "tcp", Address: "198.51.100.9", Port: "8443"},
		},
	}
	srv.singboxInvMu.Unlock()
	for i := 0; i < 3; i++ {
		post()
		now = now.Add(10 * time.Second)
	}
	if got := logs.linesWith("no longer refused"); len(got) != 1 || got[0] != "linemeta: queue sync for node-a: no longer refused" {
		t.Fatalf("recovery lines = %q, want one", got)
	}
	if !committed() {
		t.Fatal("the recovered sync did not commit its fingerprint")
	}
	srv.linemetaSyncMu.Lock()
	_, kept := srv.linemetaRefusals["node-a"]
	srv.linemetaSyncMu.Unlock()
	if kept {
		t.Fatal("the refusal entry outlived the recovery")
	}
	if n := len(refusals()); n != 2 {
		t.Fatalf("recovery logged another refusal: %d lines", n)
	}
}

// The decision on its own: a different field is news, the hour is measured
// from the last line written, and one node never quiets another.
func TestLineMetaRefusalLogDecision(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	now := time.Date(2026, 10, 3, 4, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	logs := &lockedLog{}
	srv.logger = log.New(logs, "", 0)
	refuse := func(nodeID, lost string) {
		srv.linemetaSyncMu.Lock()
		defer srv.linemetaSyncMu.Unlock()
		srv.logLineMetaRefusalLocked(nodeID, &lineMetaRegressionError{nodeID: nodeID, lost: lost})
	}
	count := func(substr string) int { return len(logs.linesWith(substr)) }

	refuse("node-a", "chain.downstream_node on hub.json")
	refuse("node-a", "chain.downstream_node on hub.json")
	if n := count("node-a would drop"); n != 1 {
		t.Fatalf("identical refusal logged %d times", n)
	}
	refuse("node-a", "line_uuid on direct.json")
	if n := count("node-a would drop line_uuid on direct.json"); n != 1 {
		t.Fatalf("a different field was not logged: %d", n)
	}
	refuse("node-a", "chain.downstream_node on hub.json")
	if n := count("node-a would drop chain.downstream_node"); n != 2 {
		t.Fatalf("a field coming back after another was not logged: %d", n)
	}
	refuse("node-b", "chain.downstream_node on hub.json")
	if n := count("node-b would drop"); n != 1 {
		t.Fatalf("node-a's refusal quieted node-b's: %d", n)
	}

	now = now.Add(lineMetaRefusalRelog - time.Second)
	refuse("node-a", "chain.downstream_node on hub.json")
	if n := count("node-a would drop chain.downstream_node"); n != 2 {
		t.Fatalf("logged again before the hour: %d", n)
	}
	now = now.Add(time.Second)
	refuse("node-a", "chain.downstream_node on hub.json")
	if got := logs.linesWith("node-a would drop chain.downstream_node"); len(got) != 3 || !strings.Contains(got[2], "(1 more since 2026-10-03T04:00:00Z)") {
		t.Fatalf("hourly line = %q", got)
	}
	// Quiet again for the next hour, measured from that line.
	now = now.Add(30 * time.Minute)
	refuse("node-a", "chain.downstream_node on hub.json")
	if n := count("node-a would drop chain.downstream_node"); n != 3 {
		t.Fatalf("logged again within the new hour: %d", n)
	}
}

// The state is per node and goes with the node.
func TestNodeDeleteForgetsLineMetaSyncState(t *testing.T) {
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
	nodeID, _ := enrollNode(t, handler, cookies, csrf)

	srv.linemetaSyncMu.Lock()
	srv.linemetaSyncFP = map[string]string{nodeID: "fp", "node-other": "fp"}
	srv.linemetaSyncMu.Unlock()
	srv.logger = log.New(&lockedLog{}, "", 0)
	srv.linemetaSyncMu.Lock()
	srv.logLineMetaRefusalLocked(nodeID, &lineMetaRegressionError{nodeID: nodeID, lost: "node_uuid"})
	srv.logLineMetaRefusalLocked("node-other", &lineMetaRegressionError{nodeID: "node-other", lost: "node_uuid"})
	srv.linemetaSyncMu.Unlock()

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/delete", `{"node_id":"`+nodeID+`"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", res.StatusCode)
	}
	srv.linemetaSyncMu.Lock()
	defer srv.linemetaSyncMu.Unlock()
	if _, ok := srv.linemetaRefusals[nodeID]; ok {
		t.Fatal("the deleted node's refusal entry survived")
	}
	if _, ok := srv.linemetaSyncFP[nodeID]; ok {
		t.Fatal("the deleted node's discovery fingerprint survived")
	}
	if _, ok := srv.linemetaRefusals["node-other"]; !ok {
		t.Fatal("deleting one node dropped another node's refusal entry")
	}
	if _, ok := srv.linemetaSyncFP["node-other"]; !ok {
		t.Fatal("deleting one node dropped another node's fingerprint")
	}
}
