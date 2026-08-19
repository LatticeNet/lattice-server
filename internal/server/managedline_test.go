package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newManagedLineTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return newLinemetaTestServer(t, st)
}

// seedManagedLineNode registers one adopted node whose sing-box inventory
// carries the given discovered lines.
func seedManagedLineNode(t *testing.T, srv *Server, nodeID string, lines []model.SingBoxNode) {
	t.Helper()
	if err := srv.store.UpsertNode(model.Node{ID: nodeID, Name: "Node " + nodeID, PublicIP: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	if srv.singboxInv == nil {
		srv.singboxInv = map[string]model.SingBoxInventory{}
	}
	srv.singboxInv[nodeID] = model.SingBoxInventory{NodeID: nodeID, At: srv.now(), Status: "ok", Nodes: lines}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
}

func seedManagedLineUser(t *testing.T, srv *Server) VpnUser {
	t.Helper()
	u := VpnUser{
		ID: "vpnuser_cdcd", Email: "cdcd@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", Flow: "xtls-rprx-vision"}},
	}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func realityInventoryLines() []model.SingBoxNode {
	return []model.SingBoxNode{
		{Name: "reality-a", Protocol: "vless", Network: "reality", Address: "203.0.113.10", Port: "443", SNI: "www.microsoft.com"},
		{Name: "hy2-a", Protocol: "hysteria2", Network: "udp", Address: "203.0.113.10", Port: "30812"},
	}
}

// rolloutTestPrincipal is the operator these tests were always meant to model.
// They previously passed lineUserTestPrincipal(), which holds no scopes at all,
// and the compiler did not look. It does now: a rollout authorizes network:plan
// on every node it touches, so a scopeless caller correctly plans nothing. The
// tests encoded the unauthorized behaviour, so they are updated rather than the
// check relaxed. TestManagedLineRolloutRefusesUnauthorizedNodes covers the
// scopeless and partially-scoped cases directly.
func rolloutTestPrincipal() principal {
	return principal{Principal: rbac.Principal{ActorID: "op-1", Scopes: []string{"network:plan"}}}
}

func compileOne(t *testing.T, srv *Server, req managedLineRolloutRequest) ([]managedLinePlannedView, []managedLineSkippedView) {
	t.Helper()
	planned, skipped, err := srv.compileManagedLineRollout(context.Background(), rolloutTestPrincipal(), req)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return planned, skipped
}

func TestManagedLineRolloutCompileHappyPath(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	u := seedManagedLineUser(t, srv)

	planned, skipped := compileOne(t, srv, managedLineRolloutRequest{UserID: u.ID})
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %+v", skipped)
	}
	if len(planned) != 1 {
		t.Fatalf("planned = %d, want 1", len(planned))
	}
	pv := planned[0]
	if pv.Port != managedLineDefaultCandidatePort || pv.Tag != "lattice-mng-24443" {
		t.Fatalf("planned port/tag = %d/%q, want %d/lattice-mng-24443", pv.Port, pv.Tag, managedLineDefaultCandidatePort)
	}
	if pv.SNI != "www.microsoft.com" {
		t.Fatalf("planned sni = %q, want inherited www.microsoft.com", pv.SNI)
	}

	def, ok, err := srv.managedLineDefByUUID(pv.LineUUID)
	if err != nil || !ok {
		t.Fatalf("def not persisted: ok=%v err=%v", ok, err)
	}
	if def.RealityPrivateKey == "" || def.RealityPublicKey == "" {
		t.Fatal("def must carry the generated keypair")
	}
	if def.Status != managedLineStatusPlanned || def.ApprovalID != pv.ApprovalID {
		t.Fatalf("def status/approval = %q/%q", def.Status, def.ApprovalID)
	}
	if def.LineHashID != managedLinePlannedHash("node-a", def.Tag, def.Port) {
		t.Fatalf("def hash %q does not match the planned discovery hash", def.LineHashID)
	}
	if def.UserName != userLineName(u.ID, def.LineUUID) {
		t.Fatalf("user name %q breaks the design-15 §5 rule", def.UserName)
	}
	// The allocated line_uuid is durable: the post-apply rediscovery must land
	// on it through the same line_hash_id.
	entry, ok := srv.store.KVEntry(lineUUIDKVBucket, def.LineHashID)
	if !ok || entry.Value != def.LineUUID {
		t.Fatalf("line_uuid KV = %q/%v, want %q", entry.Value, ok, def.LineUUID)
	}

	approval, ok := srv.store.Approval(pv.ApprovalID)
	if !ok {
		t.Fatal("approval not persisted")
	}
	if approval.Plugin != singBoxManagedLinePlugin || approval.PluginVersion != managedLinePluginVersion ||
		approval.Service != managedLineService || approval.Method != managedLineMethod {
		t.Fatalf("typed binding wrong: %+v", approval)
	}
	if approval.Action != managedLineActionPrefix+def.FragmentSHA256 || approval.ArtifactDigest != def.FragmentSHA256 {
		t.Fatal("approval action/digest does not bind the fragment SHA")
	}
	if approval.RequestSHA256 != managedLineRequestSHA(u.ID, "node-a", def.Port) {
		t.Fatal("approval request SHA mismatch")
	}
	if len(approval.Targets) != 1 || approval.Targets[0] != "node-a" {
		t.Fatalf("targets = %v", approval.Targets)
	}
	// The operator-reviewed plan must be redacted: no private key, no user
	// credential — names, public key and hashes only.
	if strings.Contains(approval.Plan, def.RealityPrivateKey) {
		t.Fatal("approval plan leaks the reality private key")
	}
	if strings.Contains(approval.Plan, u.Credentials[0].UUID) {
		t.Fatal("approval plan leaks the user credential")
	}
	if !strings.Contains(approval.Plan, def.RealityPublicKey) || !strings.Contains(approval.Plan, def.UserName) {
		t.Fatal("approval plan should carry the public key and the on-box user name")
	}
}

func TestManagedLineRolloutPlansNextFreePort(t *testing.T) {
	srv := newManagedLineTestServer(t)
	lines := append(realityInventoryLines(), model.SingBoxNode{
		Name: "taken", Protocol: "vless", Network: "tcp", Address: "203.0.113.10", Port: strconv.Itoa(managedLineDefaultCandidatePort),
	})
	seedManagedLineNode(t, srv, "node-a", lines)
	u := seedManagedLineUser(t, srv)

	planned, _ := compileOne(t, srv, managedLineRolloutRequest{UserID: u.ID})
	if len(planned) != 1 {
		t.Fatalf("planned = %d, want 1", len(planned))
	}
	if planned[0].Port != managedLineDefaultCandidatePort+1 || planned[0].Tag != "lattice-mng-24444" {
		t.Fatalf("port conflict not planned around: %+v", planned[0])
	}
}

func TestManagedLineRolloutSkips(t *testing.T) {
	srv := newManagedLineTestServer(t)
	u := seedManagedLineUser(t, srv)
	// No reality line: camouflage evidence missing (design-17 D6).
	seedManagedLineNode(t, srv, "node-plain", []model.SingBoxNode{
		{Name: "vmess-a", Protocol: "vmess", Network: "ws", Address: "203.0.113.10", Port: "443"},
	})
	// Unhealthy inventory.
	seedManagedLineNode(t, srv, "node-sick", realityInventoryLines())
	srv.singboxInvMu.Lock()
	sick := srv.singboxInv["node-sick"]
	sick.Status = "error"
	sick.Error = "probe failed"
	srv.singboxInv["node-sick"] = sick
	srv.singboxInvMu.Unlock()

	planned, skipped := compileOne(t, srv, managedLineRolloutRequest{UserID: u.ID})
	if len(planned) != 0 {
		t.Fatalf("planned = %d, want 0", len(planned))
	}
	reasons := map[string]string{}
	for _, sk := range skipped {
		reasons[sk.NodeID] = sk.Reason
	}
	if !strings.Contains(reasons["node-plain"], "camouflage") {
		t.Fatalf("node-plain reason = %q", reasons["node-plain"])
	}
	if !strings.Contains(reasons["node-sick"], "not healthy") {
		t.Fatalf("node-sick reason = %q", reasons["node-sick"])
	}
}

func TestManagedLineRolloutIdempotentSkipAndReplanAfterFailure(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	u := seedManagedLineUser(t, srv)

	planned, _ := compileOne(t, srv, managedLineRolloutRequest{UserID: u.ID})
	if len(planned) != 1 {
		t.Fatalf("planned = %d, want 1", len(planned))
	}
	// A second rollout must not double-plan the node.
	planned2, skipped2 := compileOne(t, srv, managedLineRolloutRequest{UserID: u.ID})
	if len(planned2) != 0 || len(skipped2) != 1 || !strings.Contains(skipped2[0].Reason, "already planned") {
		t.Fatalf("re-run planned=%v skipped=%v", planned2, skipped2)
	}

	// After a failed apply, a re-run re-plans in place: same port, tag and
	// line_uuid, fresh approval.
	def, _, _ := srv.managedLineDefByUUID(planned[0].LineUUID)
	def.Status = managedLineStatusFailed
	def.LastError = "sing-box check failed"
	if err := srv.putManagedLineDef(def); err != nil {
		t.Fatal(err)
	}
	planned3, skipped3 := compileOne(t, srv, managedLineRolloutRequest{UserID: u.ID})
	if len(skipped3) != 0 || len(planned3) != 1 {
		t.Fatalf("re-plan after failure: planned=%v skipped=%v", planned3, skipped3)
	}
	if planned3[0].LineUUID != planned[0].LineUUID || planned3[0].Port != planned[0].Port || planned3[0].Tag != planned[0].Tag {
		t.Fatalf("re-plan lost identity continuity: %+v vs %+v", planned3[0], planned[0])
	}
	if planned3[0].ApprovalID == planned[0].ApprovalID {
		t.Fatal("re-plan must file a fresh approval")
	}
}

func TestManagedLineFragmentHashParity(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	u := seedManagedLineUser(t, srv)
	planned, _ := compileOne(t, srv, managedLineRolloutRequest{UserID: u.ID})
	def, _, _ := srv.managedLineDefByUUID(planned[0].LineUUID)
	cred, err := lineUserCredential(u, model.ProxyProtocolVLESS, def.UserName)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := managedLineFragmentBytes(def, cred)
	if err != nil {
		t.Fatal(err)
	}
	// The fragment must not carry keys discovery would surface differently:
	// no "listen" (probe reports listen_host=""), no "route" (outbound_ref="").
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, has := decoded["route"]; has {
		t.Fatal("fragment must not declare routes; discovery outbound_ref parity breaks")
	}
	inbound := decoded["inbounds"].([]any)[0].(map[string]any)
	if _, has := inbound["listen"]; has {
		t.Fatal("fragment must not set listen; discovery listen_host parity breaks")
	}
	if inbound["type"] != "vless" || inbound["tag"] != def.Tag {
		t.Fatalf("fragment inbound = %v/%v", inbound["type"], inbound["tag"])
	}
	// Discovery maps the fragment to (node, sing-box, vless, "", port, tag, "")
	// — the hash the compiler pre-computed.
	discoveredHash := lineHash("node-a", model.ProxyCoreSingbox, model.ProxyProtocolVLESS, "", def.Port, def.Tag, "")
	if discoveredHash != def.LineHashID {
		t.Fatalf("discovery hash %q != planned %q", discoveredHash, def.LineHashID)
	}
	// The shape sing-box check will validate: reality handshake, user, short id.
	tls := inbound["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	handshake := reality["handshake"].(map[string]any)
	if handshake["server"] != def.SNI || handshake["server_port"].(float64) != 443 {
		t.Fatalf("handshake = %v", handshake)
	}
	users := inbound["users"].([]any)
	user := users[0].(map[string]any)
	if user["name"] != def.UserName || user["uuid"] != u.Credentials[0].UUID || user["flow"] != "xtls-rprx-vision" {
		t.Fatalf("fragment user = %v", user)
	}
}

func compileApproval(t *testing.T, srv *Server) (model.Approval, managedLineDef) {
	t.Helper()
	planned, skipped := compileOne(t, srv, managedLineRolloutRequest{UserID: "vpnuser_cdcd"})
	if len(planned) != 1 || len(skipped) != 0 {
		t.Fatalf("compile: planned=%v skipped=%v", planned, skipped)
	}
	approval, ok := srv.store.Approval(planned[0].ApprovalID)
	if !ok {
		t.Fatal("approval missing")
	}
	def, ok, _ := srv.managedLineDefByUUID(planned[0].LineUUID)
	if !ok {
		t.Fatal("def missing")
	}
	return approval, def
}

func TestManagedLineValidateAndApplyScript(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	u := seedManagedLineUser(t, srv)
	approval, def := compileApproval(t, srv)

	if _, _, _, err := srv.validateManagedLineApproval(approval); err != nil {
		t.Fatalf("validate: %v", err)
	}
	script := srv.managedLineApplyScript(approval)
	for _, want := range []string{"check -C", "systemctl restart sing-box", "rolled back", "__LATTICE_MANAGED_LINE_OK__", "base64 -d"} {
		if !strings.Contains(script, want) {
			t.Fatalf("apply script missing %q:\n%s", want, script)
		}
	}
	// The embedded fragment must be byte-identical to the approved render.
	marker := "FRAG_B64='"
	start := strings.Index(script, marker)
	if start < 0 {
		t.Fatal("script missing FRAG_B64")
	}
	rest := script[start+len(marker):]
	fragB64 := rest[:strings.Index(rest, "'")]
	decoded, err := base64.StdEncoding.DecodeString(fragB64)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := lineUserCredential(u, model.ProxyProtocolVLESS, def.UserName)
	if err != nil {
		t.Fatal(err)
	}
	want, err := managedLineFragmentBytes(def, cred)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(want) {
		t.Fatalf("script fragment diverged from approved bytes:\n%s\nvs\n%s", decoded, want)
	}
}

func TestManagedLineValidateFailClosed(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	seedManagedLineUser(t, srv)
	approval, def := compileApproval(t, srv)

	// (a) Credential rotation between plan and apply: the approved bytes no
	// longer exist, so the apply must fail closed instead of applying drift.
	u, _ := srv.getVpnUser("vpnuser_cdcd")
	u.Credentials[0].UUID = "11111111-2222-4333-8444-555555555555"
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := srv.validateManagedLineApproval(approval); err == nil ||
		!strings.Contains(err.Error(), "re-plan") {
		t.Fatalf("rotated credential must fail validation, got %v", err)
	}
	if script := srv.managedLineApplyScript(approval); !strings.Contains(script, "exit 1") || strings.Contains(script, "base64 -d") {
		t.Fatal("stale approval must render the fail-closed script")
	}
	// Restore for (b).
	u.Credentials[0].UUID = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}

	// (b) A line appearing on the planned port after planning conflicts.
	seedManagedLineNode(t, srv, "node-a", append(realityInventoryLines(), model.SingBoxNode{
		Name: "squatter", Protocol: "vless", Network: "tcp", Address: "203.0.113.10", Port: strconv.Itoa(def.Port),
	}))
	if _, _, _, err := srv.validateManagedLineApproval(approval); err == nil ||
		!strings.Contains(err.Error(), "port") {
		t.Fatalf("port conflict must fail validation, got %v", err)
	}
}

func TestManagedLineTaskResultReconcile(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	seedManagedLineUser(t, srv)
	approval, def := compileApproval(t, srv)

	req := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	// Failure: the definition records the reason, the approval is not applied.
	failResult := model.TaskResult{TaskID: "task_x", NodeID: "node-a", ExitCode: 1, Error: "sing-box check failed", FinishedAt: time.Now().UTC()}
	if err := srv.handleManagedLineTaskResult(req, approval, model.Task{ID: "task_x", ApprovalID: approval.ID}, failResult); err != nil {
		t.Fatal(err)
	}
	failed, _, _ := srv.managedLineDefByUUID(def.LineUUID)
	if failed.Status != managedLineStatusFailed || !strings.Contains(failed.LastError, "check failed") {
		t.Fatalf("failed def = %+v", failed)
	}
	stored, _ := srv.store.Approval(approval.ID)
	if stored.Status != model.ApprovalPending || !strings.Contains(stored.Reason, "execution failed") {
		t.Fatalf("failed task must return the approval to pending with the reason, got %q %q", stored.Status, stored.Reason)
	}

	// Success: def applied, approval applied, rediscovery probe queued.
	def2 := failed
	def2.Status = managedLineStatusPlanned
	def2.LastError = ""
	if err := srv.putManagedLineDef(def2); err != nil {
		t.Fatal(err)
	}
	okResult := model.TaskResult{TaskID: "task_y", NodeID: "node-a", ExitCode: 0, FinishedAt: time.Now().UTC()}
	if err := srv.handleManagedLineTaskResult(req, approval, model.Task{ID: "task_y", ApprovalID: approval.ID}, okResult); err != nil {
		t.Fatal(err)
	}
	applied, _, _ := srv.managedLineDefByUUID(def.LineUUID)
	if applied.Status != managedLineStatusApplied || applied.LastError != "" {
		t.Fatalf("applied def = %+v", applied)
	}
	stored, _ = srv.store.Approval(approval.ID)
	if stored.Status != model.ApprovalApplied {
		t.Fatalf("approval status = %q, want applied", stored.Status)
	}
	probeQueued := false
	for _, task := range srv.store.Tasks() {
		if isSingBoxProbeTask(task) && containsString(task.Targets, "node-a") {
			probeQueued = true
		}
	}
	if !probeQueued {
		t.Fatal("successful apply must queue rediscovery")
	}
}

// The applied overlay line is rediscovered under its planned identity and the
// read model joins the definition onto it — the Lines view's managed badge.
func TestManagedLineOverlayJoinsReadModel(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	seedManagedLineUser(t, srv)
	approval, def := compileApproval(t, srv)

	// Simulate the post-apply probe: the fragment's line appears in the
	// node's inventory exactly as the parity test pinned (tag, vless, no
	// listen host, no outbound ref).
	lines := append(realityInventoryLines(), model.SingBoxNode{
		Name: def.Tag, Protocol: "vless", Network: "reality",
		Address: "203.0.113.10", Port: strconv.Itoa(def.Port), SNI: def.SNI,
	})
	seedManagedLineNode(t, srv, "node-a", lines)
	def.Status = managedLineStatusApplied
	if err := srv.putManagedLineDef(def); err != nil {
		t.Fatal(err)
	}

	ln := findLine(t, srv.buildLineGroups(), "node-a", def.Tag)
	if ln.LineHashID != def.LineHashID {
		t.Fatalf("rediscovered line hash %q != planned %q", ln.LineHashID, def.LineHashID)
	}
	if !ln.Overlay || ln.OverlayStatus != managedLineStatusApplied || ln.OverlayUser != def.UserID {
		t.Fatalf("overlay join wrong: %+v", ln)
	}
	_ = approval
}

// The Lines view drives both through the vpn-core interface bridge: the
// redacted definition listing and the rollout compile.
func TestManagedLineRPCManagedAndRollout(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seedManagedLineNode(t, srv, "node-a", realityInventoryLines())
	seedManagedLineUser(t, srv)
	// rolloutTestPrincipal, not lineUserTestPrincipal: the rollout now
	// authorizes network:plan on every node it touches, and the plugin RPC
	// carries the same principal the REST path does.
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, rolloutTestPrincipal())

	out, err := srv.vpnCoreLinesRPC(ctx, "rollout", []byte(`{"user_id":"vpnuser_cdcd"}`))
	if err != nil {
		t.Fatalf("rollout rpc: %v", err)
	}
	var rolloutResp struct {
		OK      bool                     `json:"ok"`
		Planned []managedLinePlannedView `json:"planned"`
		Skipped []managedLineSkippedView `json:"skipped"`
	}
	if err := json.Unmarshal(out, &rolloutResp); err != nil {
		t.Fatal(err)
	}
	if !rolloutResp.OK || len(rolloutResp.Planned) != 1 || len(rolloutResp.Skipped) != 0 {
		t.Fatalf("rollout rpc response = %+v", rolloutResp)
	}

	out, err = srv.vpnCoreLinesRPC(ctx, "managed", nil)
	if err != nil {
		t.Fatalf("managed rpc: %v", err)
	}
	var managedResp struct {
		ManagedLines []managedLineDefView `json:"managed_lines"`
	}
	if err := json.Unmarshal(out, &managedResp); err != nil {
		t.Fatal(err)
	}
	if len(managedResp.ManagedLines) != 1 {
		t.Fatalf("managed lines = %d, want 1", len(managedResp.ManagedLines))
	}
	view := managedResp.ManagedLines[0]
	if view.LineUUID != rolloutResp.Planned[0].LineUUID || view.Status != managedLineStatusPlanned {
		t.Fatalf("managed view = %+v", view)
	}
	// The RPC view is the redacted one — serializing it must not expose the
	// private key anywhere.
	if raw, _ := json.Marshal(view); strings.Contains(string(raw), "private") {
		t.Fatalf("managed view leaks key material: %s", raw)
	}
}

// The activation gate (design-18 E1): a plugin whose required dependency is
// missing, inactive, or out of range must not arm.
func TestUnmetActiveDependencies(t *testing.T) {
	srv := newManagedLineTestServer(t)
	seed := []model.PluginInstallation{
		{ID: "dep.active", Version: "0.8.0-alpha.7", Status: model.PluginStatusActive},
		{ID: "dep.inactive", Version: "1.0.0", Status: model.PluginStatusDisabled},
		{ID: "dep.old", Version: "0.7.0", Status: model.PluginStatusActive},
	}
	for _, inst := range seed {
		if err := srv.store.UpsertPluginInstallation(inst); err != nil {
			t.Fatal(err)
		}
	}
	manifest := plugin.Manifest{ID: "p.test", Dependencies: []plugin.DependencySpec{
		{ID: "dep.active", Version: ">=0.8.0-alpha.5"},
		{ID: "dep.inactive"},
		{ID: "dep.old", Version: ">=0.8.0"},
		{ID: "dep.missing"},
		{ID: "dep.optional-ghost", Optional: true},
	}}
	unmet := srv.unmetActiveDependencies(manifest)
	if len(unmet) != 3 {
		t.Fatalf("unmet = %v, want 3 entries (inactive, old, missing)", unmet)
	}
	joined := strings.Join(unmet, ", ")
	for _, want := range []string{"dep.inactive (not active)", "dep.old (installed 0.7.0, need >=0.8.0)", "dep.missing (not installed)"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("unmet missing %q in %q", want, joined)
		}
	}
	if strings.Contains(joined, "dep.active") || strings.Contains(joined, "optional-ghost") {
		t.Fatalf("satisfied/optional deps must not appear: %q", joined)
	}
}
