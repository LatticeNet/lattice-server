package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestLineMetaSyncQueueAndDedup(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	out, err := srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	var resp struct {
		Approval model.Approval `json:"approval"`
		Queued   bool           `json:"queued"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Queued || resp.Approval.Status != model.ApprovalPending ||
		resp.Approval.Plugin != singBoxLineMetaPlugin || resp.Approval.NodeID != "node-a" {
		t.Fatalf("approval: %+v queued=%v", resp.Approval, resp.Queued)
	}
	if !strings.HasPrefix(resp.Approval.Action, lineMetaApplyActionPrefix) {
		t.Fatalf("action: %q", resp.Approval.Action)
	}
	if !strings.Contains(resp.Approval.Plan, "lattice.singbox-metadata.v2") {
		t.Fatalf("plan is not the metadata document: %s", resp.Approval.Plan)
	}

	// Second sync of unchanged state returns the same pending approval.
	out2, err := srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	var resp2 struct {
		Approval model.Approval `json:"approval"`
		Queued   bool           `json:"queued"`
	}
	if err := json.Unmarshal(out2, &resp2); err != nil {
		t.Fatal(err)
	}
	if resp2.Queued || resp2.Approval.ID != resp.Approval.ID {
		t.Fatalf("dedup: %+v queued=%v want same approval", resp2.Approval, resp2.Queued)
	}

	// Unknown node fails.
	if _, err := srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-nope"}`)); err == nil {
		t.Fatal("unknown node: want error")
	}
}

func TestLineMetaApplyScriptBindsPlanHash(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)
	out, err := srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	script := srv.applyScriptFor(resp.Approval)
	for _, want := range []string{"/etc/sing-box/lattice-metadata.json", ".lattice-new", ".bak", "lattice.singbox-metadata.v2"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	tampered := resp.Approval
	tampered.Plan = strings.Replace(resp.Approval.Plan, `"writer"`, `"writerX"`, 1)
	stale := srv.applyScriptFor(tampered)
	if !strings.Contains(stale, "plan bytes changed since approval") || !strings.Contains(stale, "exit 1") {
		t.Fatalf("tampered plan must fail closed:\n%s", stale)
	}
}

func TestLineMetaTaskResultLadder(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)
	out, _ := srv.vpnCoreLinesSyncMetadata(lineUserTestPrincipal(), json.RawMessage(`{"node_id":"node-a"}`))
	var resp struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := srv.handleLineMetaTaskResult(r, resp.Approval, model.Task{ID: "task_1"}, model.TaskResult{ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	fresh, _ := srv.store.Approval(resp.Approval.ID)
	if fresh.Status == model.ApprovalApplied {
		t.Fatal("failed task must not mark approval applied")
	}
	if err := srv.handleLineMetaTaskResult(r, resp.Approval, model.Task{ID: "task_1"}, model.TaskResult{ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	fresh, _ = srv.store.Approval(resp.Approval.ID)
	if fresh.Status != model.ApprovalApplied {
		t.Fatalf("status: %q", fresh.Status)
	}
}

func TestDiscoveryQueuesSyncOnlyOnChange(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	inv := model.SingBoxInventory{NodeID: "node-a", Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "vless-443.json", Protocol: "vless", Port: "443", Address: "203.0.113.5"},
	}}
	ingest := func() {
		t.Helper()
		srv.singboxInvMu.Lock()
		srv.singboxInv = map[string]model.SingBoxInventory{"node-a": inv}
		srv.singboxInvMu.Unlock()
		srv.maybeQueueLineMetaSyncOnDiscovery("node-a", inv)
	}
	countPending := func() int {
		n := 0
		for _, ap := range srv.store.Approvals() {
			if ap.Plugin == singBoxLineMetaPlugin && ap.Status == model.ApprovalPending {
				n++
			}
		}
		return n
	}
	ingest()
	if countPending() != 1 {
		t.Fatalf("first report should queue one sync, got %d", countPending())
	}
	ingest()
	if countPending() != 1 {
		t.Fatalf("unchanged report must not re-queue, got %d", countPending())
	}
	// A changed line set queues a new approval.
	inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "trojan-8443.json", Protocol: "trojan", Port: "8443", Address: "203.0.113.5"})
	ingest()
	if countPending() != 2 {
		t.Fatalf("changed report should queue a second sync, got %d", countPending())
	}
	// Error reports never queue anything.
	inv.Status = "error"
	inv.Error = "sb missing"
	ingest()
	if countPending() != 2 {
		t.Fatalf("error report must not queue, got %d", countPending())
	}
}
