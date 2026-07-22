package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func lineUserTestPrincipal() principal {
	return principal{Principal: rbac.Principal{ActorID: "op-1"}}
}

// seedLineUserFixture seeds node-a with a discovered vless line plus one bound
// VpnUser, returning the resolved line and user.
func seedLineUserFixture(t *testing.T, srv *Server) (Line, VpnUser) {
	t.Helper()
	seedLinemetaNodes(t, srv)
	var line Line
	for _, g := range srv.buildLineGroups() {
		for _, ln := range g.Lines {
			if g.NodeID == "node-a" && ln.Tag == "hub-a" {
				line = ln
			}
		}
	}
	if line.LineHashID == "" {
		t.Fatal("hub-a line not resolved")
	}
	u := VpnUser{
		ID:      "vpnuser_test1",
		Email:   "alice@example.com",
		Enabled: true,
		Credentials: []VpnCredential{
			{Protocol: "vless", UUID: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", Flow: "xtls-rprx-vision"},
			{Protocol: "trojan", Password: "old-secret"},
		},
		Bindings: []LineBinding{{LineHashID: line.LineHashID, Enabled: true}},
	}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	return line, u
}

func seedManagedLineUserFixture(t *testing.T, srv *Server) (Line, VpnUser) {
	t.Helper()
	if err := srv.store.UpsertNode(model.Node{ID: "managed-a", Name: "Managed A"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyInbound(model.ProxyInbound{
		ID: "in-managed", Name: "Managed", Core: model.ProxyCoreSingbox, Protocol: model.ProxyProtocolVLESS,
		Port: 443, Transport: model.ProxyTransportTCP, Security: model.ProxySecurityReality,
		SNI: "cdn.example.com", RealityPrivateKey: "super-secret-reality-private-key",
		RealityPublicKey: "public-reality-key-123456", RealityShortIDs: []string{"aa"},
		RealityDest: "www.microsoft.com:443", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{
		ID: "managed-a", NodeID: "managed-a", Core: model.ProxyCoreSingbox,
		InboundIDs: []string{"in-managed"}, ConfigPath: "/etc/sing-box/config.json",
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyUser(model.ProxyUser{
		ID: "legacy-keepalive", Name: "Legacy", Enabled: true, UUID: "11111111-1111-4111-8111-111111111111",
		InboundIDs: []string{"in-managed"}, Status: model.ProxyUserStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyUser(model.ProxyUser{
		ID: "other-keepalive", Name: "Other", Enabled: true, UUID: "44444444-4444-4444-8444-444444444444",
		InboundIDs: []string{"in-managed"}, Status: model.ProxyUserStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	line := findLine(t, srv.buildLineGroups(), "managed-a", "in-managed")
	user := VpnUser{
		ID: "vpnuser_managed", Email: "managed@example.com", Enabled: true,
		MigratedFromProxyUser: "legacy-keepalive",
		Credentials:           []VpnCredential{{Protocol: "vless", UUID: "22222222-2222-4222-8222-222222222222", Flow: "xtls-rprx-vision"}},
	}
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	return line, user
}

func TestUserLineName(t *testing.T) {
	n1 := userLineName("vpnuser_a", "uuid-1")
	if !strings.HasPrefix(n1, "u_") || len(n1) != 18 {
		t.Fatalf("shape: %q", n1)
	}
	if n1 != userLineName("vpnuser_a", "uuid-1") {
		t.Fatal("not deterministic")
	}
	if n1 == userLineName("vpnuser_a", "uuid-2") || n1 == userLineName("vpnuser_b", "uuid-1") {
		t.Fatal("collides across line or user")
	}
	for _, c := range n1[2:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("non-hex char in %q", n1)
		}
	}
}

func TestVpnUserLinePlanAdd(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, u := seedLineUserFixture(t, srv)
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}

	req, _ := json.Marshal(map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpAdd)
	if err != nil {
		t.Fatalf("plan_add: %v", err)
	}
	var resp struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	ap := resp.Approval
	if ap.Status != model.ApprovalPending || ap.Plugin != singBoxLineUserPlugin || ap.NodeID != "node-a" {
		t.Fatalf("approval shape: %+v", ap)
	}
	if !strings.HasPrefix(ap.Action, lineUserActionPrefix) {
		t.Fatalf("action: %q", ap.Action)
	}
	if ap.PluginVersion != "design-15" || ap.Service != vpnCoreUsersAdminService || ap.Method != "apply_add" ||
		ap.RequestSHA256 != lineUserRequestSHA(u.ID, line.LineHashID) || len(ap.Targets) != 1 || ap.Targets[0] != line.NodeID {
		t.Fatalf("typed approval binding: %+v", ap)
	}
	// The reviewed plan must never carry secret material.
	if strings.Contains(ap.Plan, "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d") || strings.Contains(ap.Plan, "old-secret") {
		t.Fatalf("plan leaks secret: %s", ap.Plan)
	}
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(ap.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Op != "add" || plan.Line != "hub-a" || plan.Protocol != "vless" || plan.LineUUID == "" ||
		plan.UserName != userLineName(u.ID, plan.LineUUID) || plan.CredentialSHA256 == "" {
		t.Fatalf("plan: %+v", plan)
	}
}

func TestVpnUserLinePlanRejections(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, u := seedLineUserFixture(t, srv)
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}

	// plan_add intentionally does not require or create a binding. Runtime
	// visibility changes only after the approved on-node task succeeds.
	u2 := VpnUser{ID: "vpnuser_unbound", Email: "b@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e"}}}
	if err := srv.putVpnUser(u2); err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]string{"user_id": u2.ID, "line_hash_id": line.LineHashID})
	if _, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpAdd); err != nil {
		t.Fatalf("unbound plan_add: %v", err)
	}
	storedU2, _ := srv.getVpnUser(u2.ID)
	if len(storedU2.Bindings) != 0 {
		t.Fatalf("planning must not expose the user through bindings: %+v", storedU2.Bindings)
	}

	// Disabled user.
	u.Enabled = false
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	req, _ = json.Marshal(map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})
	if _, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpAdd); err == nil ||
		!strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled: %v", err)
	}

	// Unknown line / unknown user.
	req, _ = json.Marshal(map[string]string{"user_id": u.ID, "line_hash_id": "line_nope"})
	if _, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpAdd); err == nil {
		t.Fatal("unknown line: want error")
	}
	req, _ = json.Marshal(map[string]string{"user_id": "vpnuser_nope", "line_hash_id": line.LineHashID})
	if _, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpAdd); err == nil {
		t.Fatal("unknown user: want error")
	}
}

func TestLineUserApplyScript(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, u := seedLineUserFixture(t, srv)
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}

	req, _ := json.Marshal(map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpAdd)
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
	if !strings.Contains(script, "user add") || !strings.Contains(script, "hub-a") ||
		!strings.Contains(script, "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d") ||
		!strings.Contains(script, "xtls-rprx-vision") {
		t.Fatalf("script:\n%s", script)
	}
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(resp.Approval.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, plan.UserName) {
		t.Fatalf("script missing derived user name %q:\n%s", plan.UserName, script)
	}
	payload, err := lineUserCredential(u, plan.Protocol, plan.UserName)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, _ := json.Marshal(payload)
	wantAdd := "\"$SB_BIN\" --json user add " + shellQuote(plan.Line) + " " + shellQuote(string(payloadJSON)) + "\n"
	if !strings.Contains(script, wantAdd) {
		t.Fatalf("add argv mismatch: want %q in:\n%s", wantAdd, script)
	}

	// Credential drift between approval and apply must fail closed.
	u.Credentials[0].UUID = "2af49c3e-1d5b-4e7a-8c9d-0e1f2a3b4c5d"
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	stale := srv.applyScriptFor(resp.Approval)
	if !strings.Contains(stale, "credential changed since approval") || !strings.Contains(stale, "exit 1") {
		t.Fatalf("stale credential must fail closed:\n%s", stale)
	}
	tampered := resp.Approval
	tampered.Service = "latticenet.vpn-core/other"
	if script := srv.applyScriptFor(tampered); !strings.Contains(script, "typed approval plugin/service binding is invalid") || !strings.Contains(script, "exit 1") {
		t.Fatalf("typed-column tamper must fail closed:\n%s", script)
	}
}

func TestLineUserRemoveScriptUsesNameArgv(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, user := seedLineUserFixture(t, srv)
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, map[string]string{
		"user_id": user.ID, "line_hash_id": line.LineHashID,
	}), lineUserOpRemove)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(response.Approval.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	script := srv.applyScriptFor(response.Approval)
	want := "\"$SB_BIN\" user del " + shellQuote(plan.Line) + " " + shellQuote(plan.UserName) + "\n"
	if !strings.Contains(script, want) {
		t.Fatalf("remove argv mismatch: want %q in:\n%s", want, script)
	}
	if strings.Contains(script, user.Credentials[0].UUID) {
		t.Fatalf("remove task must not carry credential bytes:\n%s", script)
	}
}

func TestLineUserUpdateUsesAdoptedAddContract(t *testing.T) {
	st, _ := store.Open("")
	srv := newLinemetaTestServer(t, st)
	line, user := seedLineUserFixture(t, srv)
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, map[string]string{
		"user_id": user.ID, "line_hash_id": line.LineHashID,
	}), lineUserOpUpdate)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Approval model.Approval `json:"approval"`
	}
	_ = json.Unmarshal(out, &response)
	script := srv.applyScriptFor(response.Approval)
	if !strings.Contains(script, `"$SB_BIN" --json user add `) || response.Approval.Method != "apply_update" {
		t.Fatalf("adopted update contract: approval=%+v script=%s", response.Approval, script)
	}
}

func TestManagedLineUserPlanApplyAndRemove(t *testing.T) {
	st, _ := store.Open("")
	srv := newLinemetaTestServer(t, st)
	line, user := seedManagedLineUserFixture(t, srv)
	request := mustJSON(t, map[string]string{"user_id": user.ID, "line_hash_id": line.LineHashID})
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), request, lineUserOpAdd)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	var plan lineUserPlan
	_ = json.Unmarshal([]byte(response.Approval.Plan), &plan)
	if plan.Track != lineUserTrackManaged || plan.ConfigSHA256 == "" || response.Approval.ArtifactDigest != plan.ConfigSHA256 {
		t.Fatalf("managed plan binding: plan=%+v approval=%+v", plan, response.Approval)
	}
	script := srv.applyScriptFor(response.Approval)
	for _, want := range []string{"sing-box check", "systemctl reload sing-box", user.Credentials[0].UUID, userLineName(user.ID, line.LineUUID)} {
		if !strings.Contains(script, want) {
			t.Fatalf("managed full-config script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "sb user add") {
		t.Fatalf("managed track must use full-config apply:\n%s", script)
	}
	if strings.Contains(script, `"Legacy"`) || strings.Contains(script, "11111111-1111-4111-8111-111111111111") {
		t.Fatalf("managed candidate retained the migrated legacy render row:\n%s", script)
	}
	requestHTTP := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := srv.handleLineUserTaskResult(requestHTTP, response.Approval, model.Task{ID: "managed-add"}, model.TaskResult{}); err != nil {
		t.Fatal(err)
	}
	stored, _ := srv.getVpnUser(user.ID)
	if !vpnUserHasEnabledBinding(stored, line.LineHashID) {
		t.Fatalf("managed add did not reconcile binding: %+v", stored.Bindings)
	}
	if stored.MigratedFromProxyUser != "" {
		t.Fatalf("managed apply did not finish canonical migration: %+v", stored)
	}
	if legacy, ok := srv.store.ProxyUser("legacy-keepalive"); ok {
		t.Fatalf("managed apply retained legacy render substrate: %+v", legacy)
	}
	profile, _ := srv.store.ProxyNodeProfile(line.NodeID)
	if profile.AppliedSHA256 != plan.ConfigSHA256 {
		t.Fatalf("managed applied SHA: %+v", profile)
	}
	probeFound := false
	for _, task := range srv.store.Tasks() {
		probeFound = probeFound || isSingBoxProbeTask(task)
	}
	if !probeFound {
		t.Fatal("successful managed apply did not queue bounded rediscovery")
	}
	stored.Credentials[0].UUID = "33333333-3333-4333-8333-333333333333"
	if err := srv.putVpnUser(stored); err != nil {
		t.Fatal(err)
	}
	updateOut, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), request, lineUserOpUpdate)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(updateOut, &response)
	updateScript := srv.applyScriptFor(response.Approval)
	if response.Approval.Method != "apply_update" || !strings.Contains(updateScript, stored.Credentials[0].UUID) || !strings.Contains(updateScript, "sing-box check") {
		t.Fatalf("managed update candidate is wrong: approval=%+v\n%s", response.Approval, updateScript)
	}
	if err := srv.handleLineUserTaskResult(requestHTTP, response.Approval, model.Task{ID: "managed-update"}, model.TaskResult{}); err != nil {
		t.Fatal(err)
	}

	removeOut, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), request, lineUserOpRemove)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(removeOut, &response)
	removeScript := srv.applyScriptFor(response.Approval)
	if strings.Contains(removeScript, stored.Credentials[0].UUID) || !strings.Contains(removeScript, "sing-box check") {
		t.Fatalf("managed remove candidate is wrong:\n%s", removeScript)
	}
	if err := srv.handleLineUserTaskResult(requestHTTP, response.Approval, model.Task{ID: "managed-remove"}, model.TaskResult{}); err != nil {
		t.Fatal(err)
	}
	stored, _ = srv.getVpnUser(user.ID)
	if vpnUserHasEnabledBinding(stored, line.LineHashID) {
		t.Fatalf("managed remove did not reconcile binding: %+v", stored.Bindings)
	}
}

func TestVpnUserRotateCredential(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	_, u := seedLineUserFixture(t, srv)

	req, _ := json.Marshal(map[string]string{"user_id": u.ID, "protocol": "vless"})
	out, err := srv.vpnUserRotateCredential(lineUserTestPrincipal(), req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	var resp struct {
		Protocol           string `json:"protocol"`
		RevealedCredential string `json:"revealed_credential"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if !proxyUUIDRe.MatchString(resp.RevealedCredential) || resp.RevealedCredential == u.Credentials[0].UUID {
		t.Fatalf("revealed: %q", resp.RevealedCredential)
	}
	stored, _ := srv.getVpnUser(u.ID)
	if stored.Credentials[0].UUID != resp.RevealedCredential {
		t.Fatal("store not updated to revealed uuid")
	}
	if stored.Credentials[1].Password != "old-secret" {
		t.Fatal("unrelated credential must stay unchanged")
	}

	// Password protocol rotates its password.
	req, _ = json.Marshal(map[string]string{"user_id": u.ID, "protocol": "trojan"})
	out, err = srv.vpnUserRotateCredential(lineUserTestPrincipal(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.RevealedCredential) != 24 || resp.RevealedCredential == "old-secret" {
		t.Fatalf("password reveal: %q", resp.RevealedCredential)
	}

	// Missing credential / bad protocol / unknown user.
	req, _ = json.Marshal(map[string]string{"user_id": u.ID, "protocol": "hysteria2"})
	if _, err := srv.vpnUserRotateCredential(lineUserTestPrincipal(), req); err == nil {
		t.Fatal("missing credential: want error")
	}
	req, _ = json.Marshal(map[string]string{"user_id": u.ID, "protocol": "bogus"})
	if _, err := srv.vpnUserRotateCredential(lineUserTestPrincipal(), req); err == nil {
		t.Fatal("bad protocol: want error")
	}
	req, _ = json.Marshal(map[string]string{"user_id": "vpnuser_nope", "protocol": "vless"})
	if _, err := srv.vpnUserRotateCredential(lineUserTestPrincipal(), req); err == nil {
		t.Fatal("unknown user: want error")
	}
}

func TestLineUserTaskResult(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, u := seedLineUserFixture(t, srv)

	req, _ := json.Marshal(map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpRemove)
	if err != nil {
		t.Fatalf("plan_remove: %v", err)
	}
	var resp struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/agent/task-result", nil)

	// Failed task: approval is NOT applied.
	if err := srv.handleLineUserTaskResult(r, resp.Approval, model.Task{ID: "task_1"}, model.TaskResult{ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	fresh, _ := srv.store.Approval(resp.Approval.ID)
	if fresh.Status == model.ApprovalApplied {
		t.Fatal("failed task must not mark approval applied")
	}

	// Successful remove: applied + binding dropped.
	if err := srv.handleLineUserTaskResult(r, resp.Approval, model.Task{ID: "task_1"}, model.TaskResult{ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	fresh, _ = srv.store.Approval(resp.Approval.ID)
	if fresh.Status != model.ApprovalApplied {
		t.Fatalf("status: %q", fresh.Status)
	}
	stored, _ := srv.getVpnUser(u.ID)
	for _, b := range stored.Bindings {
		if b.LineHashID == line.LineHashID {
			t.Fatal("applied remove must drop the binding")
		}
	}
}

func TestLineUserAddBindsOnlyAfterSuccessfulTask(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, user := seedLineUserFixture(t, srv)
	user.Bindings = nil
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, map[string]string{
		"user_id": user.ID, "line_hash_id": line.LineHashID,
	}), lineUserOpAdd)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := srv.handleLineUserTaskResult(request, response.Approval, model.Task{ID: "task-add"}, model.TaskResult{ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	stored, _ := srv.getVpnUser(user.ID)
	if len(stored.Bindings) != 0 {
		t.Fatalf("failed apply must not bind: %+v", stored.Bindings)
	}
	if err := srv.handleLineUserTaskResult(request, response.Approval, model.Task{ID: "task-add"}, model.TaskResult{}); err != nil {
		t.Fatal(err)
	}
	stored, _ = srv.getVpnUser(user.ID)
	if len(stored.Bindings) != 1 || stored.Bindings[0].LineHashID != line.LineHashID || !stored.Bindings[0].Enabled {
		t.Fatalf("successful add must create enabled binding: %+v", stored.Bindings)
	}
}

func TestUserLineNameIndexExplicitlyDegradesNativeVpnUser(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, user := seedLineUserFixture(t, srv)
	user.MigratedFromProxyUser = ""
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	name := userLineName(user.ID, line.LineUUID)
	target, ok := srv.userLineNameIndex()[name]
	if !ok || target.VpnUserID != user.ID || target.LineHashID != line.LineHashID || target.ProxyUserID != user.ID {
		t.Fatalf("native VpnUser must use its canonical accounting key: %+v ok=%v", target, ok)
	}
	snapshot := model.ProxyUsageSnapshot{UserBytes: map[string]int64{name: 123}}
	foldUserLineUsage(&snapshot, srv.userLineNameIndex())
	if snapshot.UserBytes[user.ID] != 123 || snapshot.LineUserBytes[line.LineHashID][user.ID] != 123 {
		t.Fatalf("native VpnUser canonical accounting fold: %+v", snapshot)
	}
}

// design-15 §8: a singbox-stats snapshot's u_<hash> counters are reversed into
// (line, proxy user) rows — the per-user total advances through the normal
// monotonic diff and the line granularity persists in line_user_bytes.
func TestFoldUserLineUsageEndToEnd(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, _ := seedLineUserFixture(t, srv)
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{ID: "proxy-a", NodeID: "node-a", Core: "sing-box", InboundIDs: []string{}}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyUser(model.ProxyUser{ID: "pu-1", Name: "alice@example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	srv.migrateProxyUsersToVpnUsers()
	migrated, ok := srv.getVpnUser("vu_pu-1")
	if !ok {
		t.Fatal("migration did not produce vu_pu-1")
	}
	migrated.Bindings = []LineBinding{{LineHashID: line.LineHashID, Enabled: true}}
	if err := srv.putVpnUser(migrated); err != nil {
		t.Fatal(err)
	}
	name := userLineName(migrated.ID, line.LineUUID)
	if got := srv.userLineNameIndex()[name]; got.LineHashID != line.LineHashID || got.ProxyUserID != "pu-1" {
		t.Fatalf("index: %+v", got)
	}

	report := func(up, down int64) {
		t.Helper()
		_, err := srv.applyProxyUsageSnapshot(model.ProxyUsageSnapshot{
			NodeID: "node-a", At: srv.now(), CoreUptimeSec: 1000,
			UserBytes: map[string]int64{name: up + down, "u_unknown1234567": 55},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	report(100, 250) // baseline
	report(160, 400) // delta 310

	user, ok := srv.store.ProxyUser("pu-1")
	if !ok {
		t.Fatal("proxy user missing")
	}
	if user.UsedBytes != 210 { // (560-350) across both directions
		t.Fatalf("UsedBytes = %d, want 210", user.UsedBytes)
	}
	snapshot, ok := srv.store.ProxyUsageSnapshot("node-a")
	if !ok {
		t.Fatal("snapshot missing")
	}
	if snapshot.UserBytes[name] != 0 {
		t.Fatalf("u_name must be folded away: %+v", snapshot.UserBytes)
	}
	if snapshot.UserBytes["pu-1"] != 560 {
		t.Fatalf("folded total: %+v", snapshot.UserBytes)
	}
	lineBucket := snapshot.LineUserBytes[line.LineHashID]
	if lineBucket["pu-1"] != 560 {
		t.Fatalf("line bucket: %+v", snapshot.LineUserBytes)
	}
	// Unknown u_ names degrade to ignored, never to fabricated traffic.
	if snapshot.UserBytes["u_unknown1234567"] != 0 {
		t.Fatalf("unknown name must be dropped by eligibility: %+v", snapshot.UserBytes)
	}
}

// The same user on two lines sums into one proxy-user total while each line
// keeps its own bucket.
func TestFoldUserLineUsageTwoLines(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)
	hub := findLine(t, srv.buildLineGroups(), "node-a", "hub-a")
	direct := findLine(t, srv.buildLineGroups(), "node-a", "direct-a")
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{ID: "proxy-a", NodeID: "node-a", Core: "sing-box"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyUser(model.ProxyUser{ID: "pu-2", Name: "bob@example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	srv.migrateProxyUsersToVpnUsers()
	u, _ := srv.getVpnUser("vu_pu-2")
	u.Bindings = []LineBinding{{LineHashID: hub.LineHashID, Enabled: true}, {LineHashID: direct.LineHashID, Enabled: true}}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	nameHub := userLineName(u.ID, hub.LineUUID)
	nameDirect := userLineName(u.ID, direct.LineUUID)
	if nameHub == nameDirect {
		t.Fatal("names must differ per line")
	}
	if _, err := srv.applyProxyUsageSnapshot(model.ProxyUsageSnapshot{
		NodeID: "node-a", At: srv.now(), CoreUptimeSec: 1000,
		UserBytes: map[string]int64{nameHub: 100, nameDirect: 40},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.applyProxyUsageSnapshot(model.ProxyUsageSnapshot{
		NodeID: "node-a", At: srv.now(), CoreUptimeSec: 1001,
		UserBytes: map[string]int64{nameHub: 150, nameDirect: 90},
	}); err != nil {
		t.Fatal(err)
	}
	user, _ := srv.store.ProxyUser("pu-2")
	if user.UsedBytes != 100 { // (150-100) + (90-40)
		t.Fatalf("UsedBytes = %d, want 100", user.UsedBytes)
	}
	snapshot, _ := srv.store.ProxyUsageSnapshot("node-a")
	if snapshot.LineUserBytes[hub.LineHashID]["pu-2"] != 150 || snapshot.LineUserBytes[direct.LineHashID]["pu-2"] != 90 {
		t.Fatalf("line buckets: %+v", snapshot.LineUserBytes)
	}
	if snapshot.UserBytes["pu-2"] != 240 {
		t.Fatalf("summed total: %+v", snapshot.UserBytes)
	}
}

func TestNativeVpnUserUsagePersistsUnderCanonicalID(t *testing.T) {
	st, _ := store.Open("")
	srv := newLinemetaTestServer(t, st)
	line, user := seedLineUserFixture(t, srv)
	user.MigratedFromProxyUser = ""
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{ID: "node-a", NodeID: "node-a", Core: model.ProxyCoreSingbox}); err != nil {
		t.Fatal(err)
	}
	name := userLineName(user.ID, line.LineUUID)
	for _, value := range []int64{100, 175} {
		if _, err := srv.applyProxyUsageSnapshot(model.ProxyUsageSnapshot{
			NodeID: "node-a", At: srv.now(), CoreUptimeSec: 100,
			UserBytes: map[string]int64{name: value},
		}); err != nil {
			t.Fatal(err)
		}
	}
	projection, ok := srv.store.ProxyUser(user.ID)
	if !ok || projection.UsedBytes != 75 {
		t.Fatalf("canonical usage projection: %+v ok=%v", projection, ok)
	}
	snapshot, _ := srv.store.ProxyUsageSnapshot("node-a")
	if snapshot.UserBytes[user.ID] != 175 || snapshot.LineUserBytes[line.LineHashID][user.ID] != 175 {
		t.Fatalf("canonical snapshot keys: %+v", snapshot)
	}
	byUser, _, rows, _, _ := srv.buildUsage()
	foundUser, foundRow := false, false
	for _, item := range byUser {
		foundUser = foundUser || (item.UserID == user.ID && item.UsedBytes == 75)
	}
	for _, row := range rows {
		foundRow = foundRow || (row.UserID == user.ID && row.LineHashID == line.LineHashID && row.Bytes == 175)
	}
	if !foundUser || !foundRow {
		t.Fatalf("canonical usage read model: byUser=%+v rows=%+v", byUser, rows)
	}
	before := len(srv.listVpnUsers())
	srv.migrateProxyUsersToVpnUsers()
	if after := len(srv.listVpnUsers()); after != before {
		t.Fatalf("canonical projection was remigrated: before=%d after=%d", before, after)
	}
}
