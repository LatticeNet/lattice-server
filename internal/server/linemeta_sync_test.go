package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestLineMetaSyncQueueAndDedup(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	now := time.Date(2026, 7, 22, 1, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
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
	now = now.Add(time.Second)
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
	if resp2.Approval.Plan != resp.Approval.Plan {
		t.Fatal("unchanged semantic state must retain byte-identical approved metadata")
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
	timestampTampered := resp.Approval
	timestampTampered.Plan = strings.Replace(resp.Approval.Plan, `"updated_at": "`, `"updated_at": "x`, 1)
	staleTimestamp := srv.applyScriptFor(timestampTampered)
	if !strings.Contains(staleTimestamp, "plan bytes changed since approval") {
		t.Fatalf("updated_at byte tampering must still fail closed:\n%s", staleTimestamp)
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
	// A changed line set updates the one pending approval for this node.
	inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "trojan-8443.json", Protocol: "trojan", Port: "8443", Address: "203.0.113.5"})
	ingest()
	if countPending() != 1 {
		t.Fatalf("changed report should update the one pending sync, got %d", countPending())
	}
	// Error reports never queue anything.
	inv.Status = "error"
	inv.Error = "sb missing"
	ingest()
	if countPending() != 1 {
		t.Fatalf("error report must not queue, got %d", countPending())
	}
}

func TestLineMetaHashIgnoresUpdatedAtOnly(t *testing.T) {
	base := []byte(`{"schema":"lattice.singbox-metadata.v2","node_id":"node-a","updated_at":"2026-07-22T01:00:00Z","writer":"lattice-server","inbounds":[],"reserved":{"in_config_key":"_lattice","fields":{"line_uuid":"string","node_uuid":"string","line_hash_id":"string"}}}`)
	later := []byte(strings.Replace(string(base), "2026-07-22T01:00:00Z", "2026-07-22T02:00:00Z", 1))
	changed := []byte(strings.Replace(string(base), `"node_id":"node-a"`, `"node_id":"node-b"`, 1))
	if lineMetaSemanticSHA(base) != lineMetaSemanticSHA(later) {
		t.Fatal("updated_at must not change semantic metadata hash")
	}
	if lineMetaSemanticSHA(base) == lineMetaSemanticSHA(changed) {
		t.Fatal("semantic metadata changes must change the hash")
	}
	if lineMetaSHA(base) == lineMetaSHA(later) {
		t.Fatal("exact plan hash must continue binding updated_at bytes")
	}
}

func TestLineMetaQueueConcurrentCallsKeepOnePending(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := srv.queueLineMetaSync(lineUserTestPrincipal(), "node-a")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	pending := 0
	for _, ap := range srv.store.Approvals() {
		if ap.Plugin == singBoxLineMetaPlugin && ap.NodeID == "node-a" && ap.Status == model.ApprovalPending {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("concurrent queues created %d pending approvals, want 1", pending)
	}
}

func TestDiscoveryRetriesAfterApprovalPersistenceFailure(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	inv := model.SingBoxInventory{NodeID: "node-a", Status: "ok", At: time.Now(), Nodes: []model.SingBoxNode{
		{Name: "vless-443.json", Protocol: "vless", Port: "443", Address: "203.0.113.5"},
	}}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{"node-a": inv}
	srv.singboxInvMu.Unlock()
	// Allocate and persist line UUIDs before making Save fail.
	_ = srv.buildLineGroups()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}

	fingerprint := singBoxDiscoveryFingerprint(inv)
	srv.maybeQueueLineMetaSyncOnDiscovery("node-a", inv)
	srv.linemetaSyncMu.Lock()
	_, committed := srv.linemetaSyncFP["node-a"]
	srv.linemetaSyncMu.Unlock()
	if committed {
		t.Fatal("failed approval persistence must not commit discovery fingerprint")
	}

	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	srv.maybeQueueLineMetaSyncOnDiscovery("node-a", inv)
	srv.linemetaSyncMu.Lock()
	got := srv.linemetaSyncFP["node-a"]
	srv.linemetaSyncMu.Unlock()
	if got != fingerprint {
		t.Fatalf("retry did not commit fingerprint: got %q want %q", got, fingerprint)
	}
	reopened, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	persisted := 0
	for _, ap := range reopened.Approvals() {
		if ap.Plugin == singBoxLineMetaPlugin && ap.NodeID == "node-a" && ap.Status == model.ApprovalPending {
			persisted++
		}
	}
	if persisted != 1 {
		t.Fatalf("retry did not durably persist one pending approval: %d", persisted)
	}
}
