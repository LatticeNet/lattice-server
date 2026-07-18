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

	// Missing binding.
	u2 := VpnUser{ID: "vpnuser_unbound", Email: "b@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e"}}}
	if err := srv.putVpnUser(u2); err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]string{"user_id": u2.ID, "line_hash_id": line.LineHashID})
	if _, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), req, lineUserOpAdd); err == nil ||
		!strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound: %v", err)
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

	// Credential drift between approval and apply must fail closed.
	u.Credentials[0].UUID = "2af49c3e-1d5b-4e7a-8c9d-0e1f2a3b4c5d"
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	stale := srv.applyScriptFor(resp.Approval)
	if !strings.Contains(stale, "credential changed since approval") || !strings.Contains(stale, "exit 1") {
		t.Fatalf("stale credential must fail closed:\n%s", stale)
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
