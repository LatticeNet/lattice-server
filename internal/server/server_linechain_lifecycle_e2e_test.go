//go:build linechain_lifecycle_e2e

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestLineChainPersistentServerAgentLifecycleE2E(t *testing.T) {
	agent := requireE2EFile(t, "LATTICE_AGENT_E2E_BIN")
	singbox := requireE2EFile(t, "LATTICE_SINGBOX_E2E_BIN")
	root := t.TempDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	srv, sourceUUID, targetUUID, _, target := seedLineChainFixture(t)
	// The ordinary fixture uses a shape-valid placeholder. The lifecycle gate
	// intentionally supplies a real X25519 public key accepted by sing-box.
	target.RealityPublicKey = "7YEFWE9O8F6l4a9tOj-QQ76Woa3dLj3P393ObtvQ91Q"
	if err := srv.putManagedLineDef(target); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	cookies, csrf := loginSession(t, handler)

	planBody := fmt.Sprintf(`{"source_line_uuid":%q,"target_line_uuid":%q}`, sourceUUID, targetUUID)
	var planned struct {
		Approval model.Approval `json:"approval"`
	}
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/lines/chains/plan", planBody, cookies, csrf, &planned)
	if planned.Approval.ID == "" {
		t.Fatal("persistent plan returned no approval")
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(planned.Approval.Plan)))
	approveBody := fmt.Sprintf(`{"approval_id":%q,"queue_apply":true,"plan_sha256":%q}`, planned.Approval.ID, planSHA)
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/approvals/approve", approveBody, cookies, csrf, nil)

	originalNode, _ := srv.store.Node("node-b")
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	enrolledNode, _ := srv.store.Node("node-b")
	originalNode.TokenHash = enrolledNode.TokenHash
	if err := srv.store.UpsertNode(originalNode); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-b", []string{lineChainDurableCapability})

	req, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/agent/tasks?node_id=node-b", nil)
	req.Header.Set("Authorization", "Bearer "+nodeToken)
	req.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
	res, err := httpServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var leased []agentTaskView
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&leased) != nil || len(leased) != 1 || leased[0].DurableProtocol != store.DurableProtocolLineChainV2 {
		t.Fatalf("lease=%d %+v", res.StatusCode, leased)
	}
	if strings.Contains(leased[0].Script, "credential-canary") {
		t.Fatal("leased script leaked secret canary")
	}
	const encodedPrefix = "printf '%s' '"
	encodedStart := strings.Index(leased[0].Script, encodedPrefix)
	encodedEnd := strings.Index(leased[0].Script, "' | base64 -d")
	if encodedStart < 0 || encodedEnd <= encodedStart {
		t.Fatal("leased script did not contain the canonical document wrapper")
	}
	documentBytes, err := base64.StdEncoding.DecodeString(leased[0].Script[encodedStart+len(encodedPrefix) : encodedEnd])
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Fragment *string `json:"fragment"`
	}
	if err := json.Unmarshal(documentBytes, &document); err != nil || document.Fragment == nil {
		t.Fatalf("leased document fragment: %v", err)
	}
	fragmentProbe := filepath.Join(root, "server-issued-fragment.json")
	if err := os.WriteFile(fragmentProbe, []byte(*document.Fragment), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(singbox, "check", "-c", fragmentProbe).CombinedOutput(); err != nil {
		t.Fatalf("server-issued fragment rejected by official sing-box: %v: %s", err, out)
	}

	configDir := filepath.Join(root, "conf")
	txnDir := filepath.Join(root, "txn")
	sidecar := filepath.Join(root, "lattice-metadata.json")
	binDir := filepath.Join(root, "bin")
	for _, dir := range []string{configDir, txnDir, binDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecar, []byte(fmt.Sprintf(`{"schema":"lattice.singbox-metadata.v2","unknown_root":{"keep":true},"inbounds":[{"tag":"before","line_uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},{"tag":"source-b","line_uuid":%q,"ordinary":"keep"},{"tag":"after","line_uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}]}`, sourceUUID)), 0o600); err != nil {
		t.Fatal(err)
	}
	systemctl := filepath.Join(binDir, "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", leased[0].Script)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "LATTICE_AGENT_BIN="+agent, "LATTICE_LINECHAIN_TXN_DIR="+txnDir, "LATTICE_LINECHAIN_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_SIDECAR_PATH="+sidecar, "LATTICE_TASK_ID="+leased[0].ID, "LATTICE_TASK_LEASE_ID="+leased[0].LeaseID, "LATTICE_LINECHAIN_TASK_SCRIPT_SHA256="+fmt.Sprintf("%x", sha256.Sum256([]byte(leased[0].Script))))
	// The production Manager resolves sing-box by name. The wrapper executes only
	// the official binary and preserves its diagnostics for an actionable failure.
	checkLog := filepath.Join(root, "sing-box-check.log")
	wrapper := fmt.Sprintf("#!/bin/sh\n%q \"$@\" 2>%q\nstatus=$?\ncat %q >&2\nexit $status\n", singbox, checkLog, checkLog)
	if err := os.WriteFile(filepath.Join(binDir, "sing-box"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		diagnostics, _ := os.ReadFile(checkLog)
		t.Fatalf("real agent helper failed: %v: %s; sing-box: %s", err, out, diagnostics)
	}
	sidecarBytes, _ := os.ReadFile(sidecar)
	if !bytes.Contains(sidecarBytes, []byte(`"unknown_root":{"keep":true}`)) || !bytes.Contains(sidecarBytes, []byte(`"ordinary":"keep"`)) {
		t.Fatalf("host fields lost: %s", sidecarBytes)
	}

	finished := time.Now().UTC().Format(time.RFC3339Nano)
	resultBody := fmt.Sprintf(`{"node_id":"node-b","result":{"task_id":%q,"lease_id":%q,"exit_code":0,"finished_at":%q}}`, leased[0].ID, leased[0].LeaseID, finished)
	// First 200 is deliberately ignored; exact replay must remain idempotent.
	for attempt := 0; attempt < 2; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/api/agent/task-result", strings.NewReader(resultBody))
		req.Header.Set("Authorization", "Bearer "+nodeToken)
		req.Header.Set("Content-Type", "application/json")
		got, err := httpServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, got.Body)
		got.Body.Close()
		if got.StatusCode != http.StatusOK {
			t.Fatalf("result replay %d", got.StatusCode)
		}
	}
	snapshot := srv.store.LineChainSnapshot()
	if snapshot.Definitions[sourceUUID].Status != store.LineChainStatusAppliedUnobserved || len(srv.store.Tasks()) != 1 {
		t.Fatalf("promotion/task mismatch: %+v tasks=%d", snapshot, len(srv.store.Tasks()))
	}

	// Reconcile the server against an ordinary agent inventory while the same
	// HTTP server remains alive. This observation is metadata-only and must not
	// create another E3 task or rewrite the target definition.
	srv.singboxInvMu.RLock()
	observed := srv.singboxInv["node-b"]
	srv.singboxInvMu.RUnlock()
	if len(observed.Nodes) != 1 {
		t.Fatalf("seeded source inventory missing: %+v", observed)
	}
	observed.Nodes[0].DownstreamLineUUID = targetUUID
	observed.Nodes[0].OutboundRef = snapshot.Definitions[sourceUUID].OutboundTag
	if err := srv.store.DeleteKV(lineUUIDKVBucket, snapshot.Definitions[sourceUUID].SourceLineHashID); err != nil {
		t.Fatal(err)
	}
	observedHash := lineHash("node-b", model.ProxyCoreSingbox, "vless", "", 1443, "source-b", observed.Nodes[0].OutboundRef)
	if err := srv.store.PutKV(model.KVEntry{Bucket: lineUUIDKVBucket, Key: observedHash, Value: sourceUUID}); err != nil {
		t.Fatal(err)
	}
	observed.Status = "ok"
	observed.At = time.Now().UTC()
	inventoryRaw, _ := json.Marshal(map[string]any{"node_id": "node-b", "inventory": observed})
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, inventoryRaw)
	if len(srv.store.Tasks()) != 1 {
		t.Fatalf("inventory queued an extra E3 task: %d", len(srv.store.Tasks()))
	}
	if got := srv.store.LineChainSnapshot().Definitions[sourceUUID]; got.Status != store.LineChainStatusConverged {
		t.Fatalf("observed apply did not converge: %+v", got)
	}
	assertDeclaredE2EEdge(t, srv.buildLineGroups(), sourceUUID, targetUUID, true)

	// An independent ordinary metadata writer may change unrelated fields. The
	// subsequent server-issued remove must preserve that drift and only remove
	// the managed chain declaration.
	projected, err := srv.renderLineMetadataJSON("node-b")
	if err != nil || !bytes.Contains(projected, []byte(sourceUUID)) || !bytes.Contains(projected, []byte(targetUUID)) {
		t.Fatalf("ordinary metadata projection lost committed chain: %s err=%v", projected, err)
	}
	var ordinary map[string]any
	if err := json.Unmarshal(projected, &ordinary); err != nil {
		t.Fatal(err)
	}
	ordinary["ordinary_sync_generation"] = float64(7)
	ordinary["unknown_root"] = map[string]any{"keep": true}
	ordinaryBytes, _ := json.Marshal(ordinary)
	if err := os.WriteFile(sidecar, ordinaryBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	var removePlanned struct {
		Approval model.Approval `json:"approval"`
	}
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/lines/chains/remove-plan", fmt.Sprintf(`{"source_line_uuid":%q}`, sourceUUID), cookies, csrf, &removePlanned)
	removePlanSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(removePlanned.Approval.Plan)))
	persistentJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/network/approvals/approve", fmt.Sprintf(`{"approval_id":%q,"queue_apply":true,"plan_sha256":%q}`, removePlanned.Approval.ID, removePlanSHA), cookies, csrf, nil)

	removeReq, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/agent/tasks?node_id=node-b", nil)
	removeReq.Header.Set("Authorization", "Bearer "+nodeToken)
	removeReq.Header.Set(agentCapabilitiesHeader, lineChainDurableCapability)
	removeRes, err := httpServer.Client().Do(removeReq)
	if err != nil {
		t.Fatal(err)
	}
	defer removeRes.Body.Close()
	var removeLeased []agentTaskView
	if removeRes.StatusCode != http.StatusOK || json.NewDecoder(removeRes.Body).Decode(&removeLeased) != nil || len(removeLeased) != 1 || removeLeased[0].DurableProtocol != store.DurableProtocolLineChainV2 {
		t.Fatalf("remove lease=%d %+v", removeRes.StatusCode, removeLeased)
	}
	removeCmd := exec.Command("sh", "-c", removeLeased[0].Script)
	removeCmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "LATTICE_AGENT_BIN="+agent, "LATTICE_LINECHAIN_TXN_DIR="+txnDir, "LATTICE_LINECHAIN_CONFIG_DIR="+configDir, "LATTICE_LINECHAIN_SIDECAR_PATH="+sidecar, "LATTICE_TASK_ID="+removeLeased[0].ID, "LATTICE_TASK_LEASE_ID="+removeLeased[0].LeaseID, "LATTICE_LINECHAIN_TASK_SCRIPT_SHA256="+fmt.Sprintf("%x", sha256.Sum256([]byte(removeLeased[0].Script))))
	if out, err := removeCmd.CombinedOutput(); err != nil {
		t.Fatalf("real agent remove helper failed: %v: %s", err, out)
	}
	removedSidecar, _ := os.ReadFile(sidecar)
	if !bytes.Contains(removedSidecar, []byte(`"ordinary_sync_generation":7`)) || !bytes.Contains(removedSidecar, []byte(`"unknown_root":{"keep":true}`)) || bytes.Contains(removedSidecar, []byte(`"downstream_line_uuid"`)) {
		t.Fatalf("remove lost ordinary metadata or retained chain: %s", removedSidecar)
	}
	removeFinished := time.Now().UTC().Format(time.RFC3339Nano)
	removeResult := fmt.Sprintf(`{"node_id":"node-b","result":{"task_id":%q,"lease_id":%q,"exit_code":0,"finished_at":%q}}`, removeLeased[0].ID, removeLeased[0].LeaseID, removeFinished)
	for attempt := 0; attempt < 2; attempt++ {
		postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/task-result", nodeToken, []byte(removeResult))
	}
	removed := srv.store.LineChainSnapshot().Definitions[sourceUUID]
	if removed.TargetLineUUID != "" || removed.Status != store.LineChainStatusAppliedUnobserved || len(srv.store.Tasks()) != 2 {
		t.Fatalf("remove promotion/task mismatch: %+v tasks=%d", removed, len(srv.store.Tasks()))
	}
	observed.Nodes[0].DownstreamLineUUID = ""
	observed.Nodes[0].OutboundRef = ""
	observed.At = time.Now().UTC()
	if err := srv.store.DeleteKV(lineUUIDKVBucket, observedHash); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutKV(model.KVEntry{Bucket: lineUUIDKVBucket, Key: snapshot.Definitions[sourceUUID].SourceLineHashID, Value: sourceUUID}); err != nil {
		t.Fatal(err)
	}
	unchainedRaw, _ := json.Marshal(map[string]any{"node_id": "node-b", "inventory": observed})
	postAgentJSON(t, httpServer.Client(), httpServer.URL+"/api/agent/singbox-inventory", nodeToken, unchainedRaw)
	removed = srv.store.LineChainSnapshot().Definitions[sourceUUID]
	if removed.Status != store.LineChainStatusConverged || removed.TargetLineUUID != "" || len(srv.store.Tasks()) != 2 {
		t.Fatalf("remove observation did not converge exactly once: %+v tasks=%d", removed, len(srv.store.Tasks()))
	}
	assertDeclaredE2EEdge(t, srv.buildLineGroups(), sourceUUID, targetUUID, false)
}

func assertDeclaredE2EEdge(t *testing.T, groups []LineGroup, sourceUUID, targetUUID string, want bool) {
	t.Helper()
	var source, target *Line
	for gi := range groups {
		for li := range groups[gi].Lines {
			line := &groups[gi].Lines[li]
			switch line.LineUUID {
			case sourceUUID:
				source = line
			case targetUUID:
				target = line
			}
		}
	}
	if source == nil || target == nil {
		t.Fatalf("source/target missing from line projection: source=%v target=%v", source, target)
	}
	got := len(source.JumpEdges) == 1 && source.JumpEdges[0] == target.LineHashID &&
		len(source.DeclaredJumpEdges) == 1 && source.DeclaredJumpEdges[0] == target.LineHashID
	if got != want {
		t.Fatalf("declared edge want=%v source=%+v target=%+v", want, source, target)
	}
}

func postAgentJSON(t *testing.T, client *http.Client, url, token string, body []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", url, res.StatusCode, raw)
	}
}

func persistentJSON(t *testing.T, client *http.Client, method, url, body string, cookies []*http.Cookie, csrf string, out any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Lattice-CSRF", csrf)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", url, res.StatusCode, raw)
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		t.Fatalf("decode %s", raw)
	}
}
func requireE2EFile(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if !filepath.IsAbs(value) {
		t.Fatalf("%s must be absolute", name)
	}
	if _, err := os.Stat(value); err != nil {
		t.Fatal(err)
	}
	return value
}
