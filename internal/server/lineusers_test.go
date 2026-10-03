package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
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

// filePlan files a line-user plan and returns its approval.
func filePlan(t *testing.T, srv *Server, op, userID, lineHashID string) model.Approval {
	t.Helper()
	out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, map[string]string{"user_id": userID, "line_hash_id": lineHashID}), op)
	if err != nil {
		t.Fatalf("plan_%s: %v", op, err)
	}
	var response struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	return response.Approval
}

func approvePlan(t *testing.T, srv *Server, approval model.Approval) error {
	t.Helper()
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	_, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), approval, true, planSHA)
	return err
}

func tasksFor(srv *Server, approvalID string) []model.Task {
	var out []model.Task
	for _, task := range srv.store.Tasks() {
		if task.ApprovalID == approvalID {
			out = append(out, task)
		}
	}
	return out
}

// Approving a line-user plan queues the apply task core renders for it, on
// both tracks. The plan fills Service and Method to bind its typed columns,
// and the approve path used to take that for a plugin operation: it marked
// the approval approved, found no loaded plugin "singbox-lineuser", and
// queued nothing.
func TestApprovingALineUserPlanQueuesItsApply(t *testing.T) {
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
	add := filePlan(t, srv, lineUserOpAdd, u.ID, line.LineHashID)
	if err := approvePlan(t, srv, add); err != nil {
		t.Fatalf("approve adopted add: %v", err)
	}
	if stored, _ := srv.store.Approval(add.ID); stored.Status != model.ApprovalApproved {
		t.Fatalf("adopted add status = %q, want approved", stored.Status)
	}
	if tasks := tasksFor(srv, add.ID); len(tasks) != 1 || !strings.Contains(tasks[0].Script, "user add "+shellQuote(line.Tag)) {
		t.Fatalf("approved adopted add must queue sb user add: %+v", tasks)
	}

	managedSrv := newLinemetaTestServer(t, mustOpenStore(t))
	managedLine, identity := seedManagedLineUserFixture(t, managedSrv)
	managedAdd := filePlan(t, managedSrv, lineUserOpAdd, identity.ID, managedLine.LineHashID)
	if err := approvePlan(t, managedSrv, managedAdd); err != nil {
		t.Fatalf("approve managed add: %v", err)
	}
	if tasks := tasksFor(managedSrv, managedAdd.ID); len(tasks) != 1 || !strings.Contains(tasks[0].Script, "/etc/sing-box/config.json") {
		t.Fatalf("approved managed add must queue the full config apply: %+v", tasks)
	}
}

// lineUserScriptPrelude is the start of every adopted line-user apply script.
const lineUserScriptPrelude = "set -e\n" +
	"SB_BIN=\"${LATTICE_SINGBOX_BIN:-sb}\"\n" +
	"command -v \"$SB_BIN\" >/dev/null 2>&1 || { echo 'lattice lineuser: sb binary not found' >&2; exit 1; }\n"

// seedMintedLineUser stores an unbound user whose id has the shape Lattice
// mints, so a removal filed after its deletion passes vpnUserIDRe.
func seedMintedLineUser(t *testing.T, srv *Server) VpnUser {
	t.Helper()
	u := VpnUser{
		ID: id.New("vpnuser"), Email: "minted@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "6a1b7c2d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", Flow: "xtls-rprx-vision"}},
	}
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

// applyLinePlanResult approves a filed plan, checks it queued one task,
// reports that task a success the way a node would, checks the approval is
// applied, and returns the task.
func applyLinePlanResult(t *testing.T, srv *Server, approval model.Approval, line Line) model.Task {
	t.Helper()
	if err := approvePlan(t, srv, approval); err != nil {
		t.Fatalf("approve: %v", err)
	}
	tasks := tasksFor(srv, approval.ID)
	if len(tasks) != 1 {
		t.Fatalf("approval queued %d task(s), want 1", len(tasks))
	}
	request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := srv.handleApprovalTaskResult(request, tasks[0], model.TaskResult{TaskID: tasks[0].ID, NodeID: line.NodeID}); err != nil {
		t.Fatalf("successful result: %v", err)
	}
	if stored, _ := srv.store.Approval(approval.ID); stored.Status != model.ApprovalApplied {
		t.Fatalf("status = %q reason %q, want applied", stored.Status, stored.Reason)
	}
	return tasks[0]
}

// applyLinePlan files a plan for userID on the line and applies it through
// applyLinePlanResult.
func applyLinePlan(t *testing.T, srv *Server, op, userID string, line Line) model.Task {
	t.Helper()
	return applyLinePlanResult(t, srv, filePlan(t, srv, op, userID, line.LineHashID), line)
}

// lineUserRemoveArgv is the argv an adopted removal runs: the same JSON
// payload the add sent, which is what the fork's cmd_json_user accepts.
func lineUserRemoveArgv(t *testing.T, u VpnUser, line Line) string {
	t.Helper()
	payload, err := lineUserCredential(u, line.Type, userLineName(u.ID, line.LineUUID))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(payload)
	return `"$SB_BIN" --json user del ` + shellQuote(line.Tag) + " " + shellQuote(string(raw)) + "\n"
}

// Deleting a user deletes the only copy of its credential, so its removal
// from an adopted line can carry the on-box name and nothing else. alpha.7
// refuses that (invalid_user, and invalid_payload for a102's bare name), and
// every task a102 filed failed on the node and returned to pending. On a node
// whose agent has not reported sb:user-del-by-name the removal is refused,
// filed before the deletion or after it, at plan time, at approval and at
// script render, with a reason that names the missing node support and the
// on-box name left behind.
func TestRemovingADeletedUserIsRefusedOnANodeThatCannotDeleteByName(t *testing.T) {
	refusal := func(t *testing.T, err error, u VpnUser, line Line) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "alpha.8") || !strings.Contains(err.Error(), userLineName(u.ID, line.LineUUID)) ||
			!strings.Contains(err.Error(), "no longer holds the credential") || !strings.Contains(err.Error(), singBoxUserDelByNameCapability) {
			t.Fatalf("want the refusal naming alpha.8, the capability and the on-box name, got %v", err)
		}
	}

	t.Run("filed after the deletion", func(t *testing.T) {
		srv, line, u := deletedLineUserFixture(t)
		if err := srv.deleteVpnUser(u.ID); err != nil {
			t.Fatal(err)
		}
		approvalsBefore, auditsBefore := len(srv.store.Approvals()), len(srv.store.AuditEvents())
		_, err := srv.vpnUserLinePlan(lineUserTestPrincipal(),
			mustJSON(t, map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID}), lineUserOpRemove)
		refusal(t, err, u, line)
		if len(srv.store.Approvals()) != approvalsBefore || len(srv.store.AuditEvents()) != auditsBefore {
			t.Fatal("a refused removal must file nothing and audit nothing")
		}
	})

	t.Run("filed before the deletion", func(t *testing.T) {
		srv, line, u := deletedLineUserFixture(t)
		approval := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
		if err := srv.deleteVpnUser(u.ID); err != nil {
			t.Fatal(err)
		}
		refusal(t, approvePlan(t, srv, approval), u, line)
		if stored, _ := srv.store.Approval(approval.ID); stored.Status != model.ApprovalPending {
			t.Fatalf("a refused approval must stay pending, got %q", stored.Status)
		}
		if tasks := tasksFor(srv, approval.ID); len(tasks) != 0 {
			t.Fatalf("a refused approval queued %d task(s)", len(tasks))
		}
		if script := srv.applyScriptFor(approval); !strings.Contains(script, "alpha.8") || !strings.Contains(script, "exit 1") {
			t.Fatalf("the script render must fail closed with the reason:\n%s", script)
		}
	})

	// a102 filed a name-only plan after the deletion; one still pending when
	// this ships must not reach a node that cannot run it either.
	t.Run("filed by a102 after the deletion", func(t *testing.T) {
		srv, line, u := deletedLineUserFixture(t)
		if err := srv.deleteVpnUser(u.ID); err != nil {
			t.Fatal(err)
		}
		approval := fileA102DeletedUserRemoval(t, srv, u, line)
		refusal(t, approvePlan(t, srv, approval), u, line)
		if tasks := tasksFor(srv, approval.ID); len(tasks) != 0 {
			t.Fatalf("a refused approval queued %d task(s)", len(tasks))
		}
	})
}

// deletedLineUserFixture is a server with an adopted vless line on node-a
// and a user of the shape Lattice mints that an applied plan put there.
func deletedLineUserFixture(t *testing.T) (*Server, Line, VpnUser) {
	t.Helper()
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, _ := seedLineUserFixture(t, srv)
	u := seedMintedLineUser(t, srv)
	applyLinePlan(t, srv, lineUserOpAdd, u.ID, line)
	return srv, line, u
}

// fileA102DeletedUserRemoval files the removal a102 filed for a deleted
// user: the name alone, hashed as the payload.
func fileA102DeletedUserRemoval(t *testing.T, srv *Server, u VpnUser, line Line) model.Approval {
	t.Helper()
	name := userLineName(u.ID, line.LineUUID)
	sha, err := lineUserCredentialSHA(lineUserCredentialPayload{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	out, err := srv.fileLineUserPlan(lineUserTestPrincipal(), lineUserPlan{
		Op: lineUserOpRemove, Track: lineUserTrackAdopted, NodeID: line.NodeID, Line: line.Tag,
		LineHashID: line.LineHashID, LineUUID: line.LineUUID, UserID: u.ID, UserName: name,
		Protocol: line.Type, CredentialSHA256: sha, Summary: "a102 deleted-user removal",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	return response.Approval
}

// deletedUserRemovalScript is the script a removal by name renders: the
// on-box name as the whole payload.
func deletedUserRemovalScript(u VpnUser, line Line) string {
	return lineUserScriptPrelude + `"$SB_BIN" --json user del ` + shellQuote(line.Tag) + " " +
		shellQuote(`{"name":"`+userLineName(u.ID, line.LineUUID)+`"}`) + "\n"
}

// On a node whose agent reports sb:user-del-by-name, a deleted user's
// removal is filed, approved and rendered with the on-box name as its whole
// payload, and the hash binds that payload like any other. A name-only
// approval a102 filed follows the node: refused while the node has not
// reported the capability, approvable once it has, refused again when a
// heartbeat drops it. An approval filed before the deletion hashed the
// credential, so it is refused with the way out: reject it and file the
// removal again, by name.
func TestRemovingADeletedUserByNameOnANodeThatReportsIt(t *testing.T) {
	capable := func(srv *Server, line Line) {
		srv.replaceAgentCapabilities(line.NodeID, []string{lineChainDurableCapability, singBoxUserDelByNameCapability})
	}

	t.Run("filed after the deletion", func(t *testing.T) {
		srv, line, u := deletedLineUserFixture(t)
		capable(srv, line)
		if err := srv.deleteVpnUser(u.ID); err != nil {
			t.Fatal(err)
		}
		approval := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
		var plan lineUserPlan
		if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil {
			t.Fatal(err)
		}
		sha, _ := lineUserCredentialSHA(lineUserCredentialPayload{Name: userLineName(u.ID, line.LineUUID)})
		if plan.Op != lineUserOpRemove || plan.CredentialSHA256 != sha || approval.Action != lineUserActionPrefix+sha ||
			approval.ArtifactDigest != sha || !strings.Contains(plan.Summary, "by name alone") {
			t.Fatalf("plan = %+v action %q digest %q, want the name-only payload's hash and a summary saying so", plan, approval.Action, approval.ArtifactDigest)
		}
		if err := approvePlan(t, srv, approval); err != nil {
			t.Fatalf("approve: %v", err)
		}
		tasks := tasksFor(srv, approval.ID)
		if len(tasks) != 1 || tasks[0].Script != deletedUserRemovalScript(u, line) {
			t.Fatalf("tasks = %+v, want one task running\n%s", tasks, deletedUserRemovalScript(u, line))
		}
		if strings.Contains(tasks[0].Script, "6a1b7c2d") {
			t.Fatal("the removal by name must not carry the deleted user's credential")
		}
	})

	t.Run("filed by a102 after the deletion", func(t *testing.T) {
		srv, line, u := deletedLineUserFixture(t)
		if err := srv.deleteVpnUser(u.ID); err != nil {
			t.Fatal(err)
		}
		approval := fileA102DeletedUserRemoval(t, srv, u, line)
		if err := approvePlan(t, srv, approval); err == nil || !strings.Contains(err.Error(), singBoxUserDelByNameCapability) {
			t.Fatalf("approve before the node reports the capability: %v, want the refusal", err)
		}
		capable(srv, line)
		srv.replaceAgentCapabilities(line.NodeID, []string{lineChainDurableCapability})
		if err := approvePlan(t, srv, approval); err == nil || !strings.Contains(err.Error(), singBoxUserDelByNameCapability) {
			t.Fatalf("approve after a heartbeat dropped the capability: %v, want the refusal", err)
		}
		if stored, _ := srv.store.Approval(approval.ID); stored.Status != model.ApprovalPending || len(tasksFor(srv, approval.ID)) != 0 {
			t.Fatalf("a refused approval must stay pending with no task, got %q", stored.Status)
		}
		capable(srv, line)
		if err := approvePlan(t, srv, approval); err != nil {
			t.Fatalf("approve once the node reports the capability: %v", err)
		}
		if tasks := tasksFor(srv, approval.ID); len(tasks) != 1 || tasks[0].Script != deletedUserRemovalScript(u, line) {
			t.Fatalf("tasks = %+v, want one task running\n%s", tasks, deletedUserRemovalScript(u, line))
		}
	})

	t.Run("filed before the deletion", func(t *testing.T) {
		srv, line, u := deletedLineUserFixture(t)
		capable(srv, line)
		approval := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
		if err := srv.deleteVpnUser(u.ID); err != nil {
			t.Fatal(err)
		}
		err := approvePlan(t, srv, approval)
		if err == nil || !strings.Contains(err.Error(), "hashed its credential") || !strings.Contains(err.Error(), "reject it and plan_remove again") {
			t.Fatalf("approve: %v, want the refusal naming the way out", err)
		}
		if stored, _ := srv.store.Approval(approval.ID); stored.Status != model.ApprovalPending || len(tasksFor(srv, approval.ID)) != 0 {
			t.Fatalf("a refused approval must stay pending with no task, got %q", stored.Status)
		}
		if script := srv.applyScriptFor(approval); !strings.Contains(script, "hashed its credential") || !strings.Contains(script, "exit 1") {
			t.Fatalf("the script render must fail closed with the reason:\n%s", script)
		}
		if err := srv.rejectApprovalWithReason(approval, "superseded by a removal by name"); err != nil {
			t.Fatal(err)
		}
		again := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
		if err := approvePlan(t, srv, again); err != nil {
			t.Fatalf("approve the removal filed again: %v", err)
		}
		if tasks := tasksFor(srv, again.ID); len(tasks) != 1 || tasks[0].Script != deletedUserRemovalScript(u, line) {
			t.Fatalf("tasks = %+v, want one task running\n%s", tasks, deletedUserRemovalScript(u, line))
		}
	})
}

// A removal for a user Lattice no longer has must name an id of the shape
// Lattice mints, refused before it is filed or echoed, and the approvals
// must show an applied plan put that user on that line with no applied
// removal since. A typo, an id that never reached the line, and a removal
// after one already applied get those narrower refusals ahead of the
// missing-credential one, and none files anything.
func TestADeletedUsersRemovalNeedsAMintedIDAndALineHistory(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, _ := seedLineUserFixture(t, srv)
	u := seedMintedLineUser(t, srv)
	applyLinePlan(t, srv, lineUserOpAdd, u.ID, line)
	applyLinePlan(t, srv, lineUserOpRemove, u.ID, line)
	if err := srv.deleteVpnUser(u.ID); err != nil {
		t.Fatal(err)
	}
	plan := func(userID string) error {
		_, err := srv.vpnUserLinePlan(lineUserTestPrincipal(),
			mustJSON(t, map[string]string{"user_id": userID, "line_hash_id": line.LineHashID}), lineUserOpRemove)
		return err
	}
	approvalsBefore := len(srv.store.Approvals())
	auditsBefore := len(srv.store.AuditEvents())

	malformed := []string{
		"",
		"vpnuser_typo1",
		"vpnuser_ABCDEFGHIJKLMNOP",
		u.ID + "x",
		u.ID + "\nforged audit line",
		"vu_" + strings.Repeat("a", 129),
		"puser_" + strings.TrimPrefix(u.ID, "vpnuser_"),
	}
	for _, userID := range malformed {
		err := plan(userID)
		if err == nil || !strings.Contains(err.Error(), "neither an existing user nor a VpnUser id Lattice mints") {
			t.Fatalf("plan_remove for malformed id %q: %v, want the format refusal", userID, err)
		}
		if userID != "" && strings.Contains(err.Error(), userID) {
			t.Fatalf("the refusal echoed the malformed id %q: %v", userID, err)
		}
	}

	neverExisted := id.New("vpnuser")
	if err := plan(neverExisted); err == nil || !strings.Contains(err.Error(), "no applied plan ever put user") {
		t.Fatalf("plan_remove for an id that never reached the line: %v, want the history refusal", err)
	}
	if got := len(srv.store.Approvals()); got != approvalsBefore {
		t.Fatalf("refused removals filed %d approval(s)", got-approvalsBefore)
	}
	if got := len(srv.store.AuditEvents()); got != auditsBefore {
		t.Fatalf("refused removals wrote %d audit event(s)", got-auditsBefore)
	}

	if err := plan(u.ID); err == nil || !strings.Contains(err.Error(), "already removed user") {
		t.Fatalf("a second removal after the first applied: %v, want the history refusal", err)
	}
}

// unbind drops only the server's binding record, so a user that plan_add put
// on an adopted line keeps its credential there, and plan_remove refused it
// as "not bound", while a removal filed before the unbind failed with "line
// binding changed since planning". Both complete now, removing only that
// user's derived name. A user with no binding and no applied plan on the
// line has nothing to remove, and a managed line, whose render already
// leaves an unbound user out, still needs the binding.
func TestRemovingAnUnboundUsersCredentialFromAnAdoptedLine(t *testing.T) {
	for _, filed := range []string{"before the unbind", "after the unbind"} {
		t.Run(filed, func(t *testing.T) {
			srv := newLinemetaTestServer(t, mustOpenStore(t))
			line, u := seedLineUserFixture(t, srv)
			u.Bindings = nil
			if err := srv.putVpnUser(u); err != nil {
				t.Fatal(err)
			}
			applyLinePlan(t, srv, lineUserOpAdd, u.ID, line)
			unbind := func() {
				t.Helper()
				if _, err := srv.vpnUserUnbind(mustJSON(t, map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})); err != nil {
					t.Fatal(err)
				}
			}
			var approval model.Approval
			if filed == "before the unbind" {
				approval = filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
				unbind()
			} else {
				unbind()
				approval = filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
				if !strings.Contains(approval.Plan, "Lattice holds no binding for this user on the line") {
					t.Fatalf("the plan must say Lattice holds no binding: %s", approval.Plan)
				}
			}
			removed := applyLinePlanResult(t, srv, approval, line)
			want := lineUserScriptPrelude + lineUserRemoveArgv(t, u, line)
			if removed.Script != want || len(removed.Targets) != 1 || removed.Targets[0] != "node-a" {
				t.Fatalf("removal task = %+v, want one task on node-a running:\n%s", removed, want)
			}
			if lineUserBoundTo(t, srv, u.ID, line.LineHashID) {
				t.Fatal("reconciling the removal bound the user again")
			}
		})
	}

	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	if _, err := srv.vpnUserUnbind(mustJSON(t, map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.vpnUserLinePlan(lineUserTestPrincipal(),
		mustJSON(t, map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID}), lineUserOpRemove); err == nil ||
		!strings.Contains(err.Error(), "no applied plan ever put user") {
		t.Fatalf("plan_remove for an unbound user no plan put on the line: %v, want the history refusal", err)
	}

	managedSrv := newLinemetaTestServer(t, mustOpenStore(t))
	managedLine, identity := seedManagedLineUserFixture(t, managedSrv)
	_, err := managedSrv.vpnUserLinePlan(lineUserTestPrincipal(),
		mustJSON(t, map[string]string{"user_id": identity.ID, "line_hash_id": managedLine.LineHashID}), lineUserOpRemove)
	if err == nil || !strings.Contains(err.Error(), "is not bound to line") {
		t.Fatalf("plan_remove on a managed line for an unbound user: %v, want not bound", err)
	}
}

// A deleted user still cannot be added or updated, and a managed line's
// removal is left to its config apply, since its render already leaves the
// user out.
func TestADeletedUserIsPlannedOnlyForRemovalFromAnAdoptedLine(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	if err := srv.deleteVpnUser(u.ID); err != nil {
		t.Fatal(err)
	}
	request := mustJSON(t, map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})
	for _, op := range []string{lineUserOpAdd, lineUserOpUpdate} {
		if _, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), request, op); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("plan_%s for a deleted user: %v, want not found", op, err)
		}
	}

	managedSrv := newLinemetaTestServer(t, mustOpenStore(t))
	managedLine, _ := seedManagedLineUserFixture(t, managedSrv)
	_, err := managedSrv.vpnUserLinePlan(lineUserTestPrincipal(),
		mustJSON(t, map[string]string{"user_id": id.New("vpnuser"), "line_hash_id": managedLine.LineHashID}), lineUserOpRemove)
	if err == nil || !strings.Contains(err.Error(), "already leaves it out of its render") {
		t.Fatalf("plan_remove on a managed line for a deleted user: %v, want the render refusal", err)
	}
}

// A second removal of the same user from the same line is refused while the
// first can still act: pending, approved with a live task, and pending again
// after a failed run. Once the first is rejected a new one can be filed, and
// an approved removal whose task was cancelled, which nothing can decide
// again, does not block the next one.
func TestASecondRemovalWaitsForTheOpenOne(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	plan := func(userID string) error {
		_, err := srv.vpnUserLinePlan(lineUserTestPrincipal(),
			mustJSON(t, map[string]string{"user_id": userID, "line_hash_id": line.LineHashID}), lineUserOpRemove)
		return err
	}
	refused := func(t *testing.T, userID string, open model.Approval, state string) {
		t.Helper()
		before := len(srv.store.Approvals())
		err := plan(userID)
		if err == nil || !strings.Contains(err.Error(), "already "+state+" as approval "+open.ID) {
			t.Fatalf("a second removal while the first is %s: %v, want a refusal naming %s", state, err, open.ID)
		}
		if got := len(srv.store.Approvals()); got != before {
			t.Fatalf("the refused removal filed %d approval(s)", got-before)
		}
	}

	first := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
	refused(t, u.ID, first, "pending")
	if err := approvePlan(t, srv, first); err != nil {
		t.Fatalf("approve: %v", err)
	}
	refused(t, u.ID, first, "approved")
	tasks := tasksFor(srv, first.ID)
	request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := srv.handleApprovalTaskResult(request, tasks[0], model.TaskResult{TaskID: tasks[0].ID, NodeID: "node-a", ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	refused(t, u.ID, first, "pending")

	decider := principal{Principal: rbac.Principal{ActorID: "decider", Scopes: []string{"network:apply", "network:plan", "vpncore:admin"}}}
	if rec := decideApproval(srv, "reject", `{"approval_id":"`+first.ID+`"}`, decider); rec.Code != 200 {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	second := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)

	// Approved with a live task, it is still open, and the refusal names the
	// task and its status.
	if err := approvePlan(t, srv, second); err != nil {
		t.Fatalf("approve the second removal: %v", err)
	}
	secondTasks := tasksFor(srv, second.ID)
	if len(secondTasks) != 1 || secondTasks[0].Status != model.TaskQueued {
		t.Fatalf("the second removal's tasks = %+v, want one queued", secondTasks)
	}
	refused(t, u.ID, second, "approved")
	if err := plan(u.ID); err == nil || !strings.Contains(err.Error(), "its task "+secondTasks[0].ID+" is queued") {
		t.Fatalf("the refusal must name the live task: %v", err)
	}

	// Approved with no live task it can never act or be decided again, so it
	// must not block the next removal. Cancelling the queued task leaves the
	// approval approved.
	if _, err := srv.store.CancelTask(secondTasks[0].ID); err != nil {
		t.Fatalf("cancel the queued task: %v", err)
	}
	if stored, _ := srv.store.Approval(second.ID); stored.Status != model.ApprovalApproved {
		t.Fatalf("after the cancel the approval is %q, want it still approved", stored.Status)
	}
	if err := plan(u.ID); err != nil {
		t.Fatalf("a removal after the approved one lost its task: %v", err)
	}

	// A removal filed before the user was deleted still holds the line, and
	// once the user is gone no other can be filed at all, because Lattice
	// lost the credential the node script removes by.
	deleted := seedMintedLineUser(t, srv)
	applyLinePlan(t, srv, lineUserOpAdd, deleted.ID, line)
	open := filePlan(t, srv, lineUserOpRemove, deleted.ID, line.LineHashID)
	refused(t, deleted.ID, open, "pending")
	if err := srv.deleteVpnUser(deleted.ID); err != nil {
		t.Fatal(err)
	}
	if err := plan(deleted.ID); err == nil || !strings.Contains(err.Error(), "alpha.8") {
		t.Fatalf("a removal for the deleted user: %v, want the missing-credential refusal", err)
	}
}

// lineUserAudit returns the audit events with action that name approvalID.
func lineUserAudit(srv *Server, action, approvalID string) []model.AuditEvent {
	var out []model.AuditEvent
	for _, ev := range srv.store.AuditEvents() {
		if ev.Action == action && ev.Metadata["approval_id"] == approvalID {
			out = append(out, ev)
		}
	}
	return out
}

// lineUserBoundTo reports whether userID holds an enabled binding to lineHashID.
func lineUserBoundTo(t *testing.T, srv *Server, userID, lineHashID string) bool {
	t.Helper()
	u, ok := srv.getVpnUser(userID)
	if !ok {
		t.Fatalf("user %q disappeared", userID)
	}
	return vpnUserHasEnabledBinding(u, lineHashID)
}

// From a102 an approved line-user plan runs sb user add or sb user del on an
// adopted node, which production has never done. Each op is pinned end to
// end: the one task approval queues, the node it targets, the exact argv it
// runs, the approve audit event, and what the task result then does to the
// binding and the approval, on a failed run and on a successful retry.
func TestApprovedAdoptedLineUserPlanRunsTheReviewedArgv(t *testing.T) {
	// The payload is spelled out rather than re-derived, so a change to the
	// credential bytes that reach sb fails here.
	userAdd := func(name string) string {
		return `"$SB_BIN" --json user add 'hub-a' '{"name":"` + name +
			`","uuid":"9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d","flow":"xtls-rprx-vision"}'` + "\n"
	}
	userDel := func(name string) string {
		return `"$SB_BIN" --json user del 'hub-a' '{"name":"` + name +
			`","uuid":"9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d","flow":"xtls-rprx-vision"}'` + "\n"
	}
	cases := []struct {
		op         string
		boundFirst bool
		argv       func(name string) string
		boundAfter bool
	}{
		{op: lineUserOpAdd, boundFirst: false, argv: userAdd, boundAfter: true},
		{op: lineUserOpUpdate, boundFirst: true, argv: userAdd, boundAfter: true},
		{op: lineUserOpRemove, boundFirst: true, argv: userDel, boundAfter: false},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			srv := newLinemetaTestServer(t, mustOpenStore(t))
			line, u := seedLineUserFixture(t, srv)
			if !tc.boundFirst {
				u.Bindings = nil
				if err := srv.putVpnUser(u); err != nil {
					t.Fatal(err)
				}
			}
			approval := filePlan(t, srv, tc.op, u.ID, line.LineHashID)
			if err := approvePlan(t, srv, approval); err != nil {
				t.Fatalf("approve: %v", err)
			}
			tasks := tasksFor(srv, approval.ID)
			if len(tasks) != 1 {
				t.Fatalf("approval queued %d tasks, want 1: %+v", len(tasks), tasks)
			}
			first := tasks[0]
			if len(first.Targets) != 1 || first.Targets[0] != "node-a" {
				t.Fatalf("task targets = %q, want exactly [node-a]", first.Targets)
			}
			want := lineUserScriptPrelude + tc.argv(userLineName(u.ID, line.LineUUID))
			if first.Script != want {
				t.Fatalf("task script:\n%s\nwant:\n%s", first.Script, want)
			}
			approves := lineUserAudit(srv, "network.singbox-lineuser.approve", approval.ID)
			if len(approves) != 1 || approves[0].Scope != "network:apply,vpncore:admin" ||
				approves[0].ActorID != "op-1" || approves[0].NodeID != "node-a" {
				t.Fatalf("approve audit = %+v, want one event by op-1 on node-a under network:apply,vpncore:admin", approves)
			}

			request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
			if err := srv.handleApprovalTaskResult(request, first, model.TaskResult{
				TaskID: first.ID, NodeID: "node-a", ExitCode: 1, Error: "sb: inbound hub-a not found",
			}); err != nil {
				t.Fatalf("failed result: %v", err)
			}
			stored, _ := srv.store.Approval(approval.ID)
			if stored.Status != model.ApprovalPending || stored.Reason != "execution failed: sb: inbound hub-a not found" {
				t.Fatalf("after a failed run: status %q reason %q, want pending with the failure", stored.Status, stored.Reason)
			}
			if got := lineUserBoundTo(t, srv, u.ID, line.LineHashID); got != tc.boundFirst {
				t.Fatalf("after a failed run bound = %v, want it unchanged at %v", got, tc.boundFirst)
			}
			if failed := lineUserAudit(srv, "vpnuser.line.failed", approval.ID); len(failed) != 1 {
				t.Fatalf("failed-run audit = %+v, want one event", failed)
			}

			// The failure returned the approval to pending, so the same plan
			// approves again and its second run reconciles.
			if err := approvePlan(t, srv, stored); err != nil {
				t.Fatalf("re-approve after a failed run: %v", err)
			}
			tasks = tasksFor(srv, approval.ID)
			if len(tasks) != 2 {
				t.Fatalf("re-approval left %d tasks, want 2: %+v", len(tasks), tasks)
			}
			retry := tasks[0]
			if retry.ID == first.ID {
				retry = tasks[1]
			}
			if retry.Script != want || len(retry.Targets) != 1 || retry.Targets[0] != "node-a" {
				t.Fatalf("retry task = %+v, want the same argv on node-a", retry)
			}
			if err := srv.handleApprovalTaskResult(request, retry, model.TaskResult{TaskID: retry.ID, NodeID: "node-a"}); err != nil {
				t.Fatalf("successful result: %v", err)
			}
			stored, _ = srv.store.Approval(approval.ID)
			if stored.Status != model.ApprovalApplied || stored.Reason != "" {
				t.Fatalf("after a successful run: status %q reason %q, want applied", stored.Status, stored.Reason)
			}
			if got := lineUserBoundTo(t, srv, u.ID, line.LineHashID); got != tc.boundAfter {
				t.Fatalf("after a successful run bound = %v, want %v", got, tc.boundAfter)
			}
			if applied := lineUserAudit(srv, "vpnuser.line.applied", approval.ID); len(applied) != 1 {
				t.Fatalf("applied audit = %+v, want one event", applied)
			}
		})
	}
}

// Approving a line-user plan without queue_apply stored it approved with no
// task, and approve is a no-op once an approval is not pending, so the plan
// could never reach the node: the dead end dd75324 fixed for queue_apply=true.
// The endpoint refuses it now and leaves the approval pending, and the same
// request with queue_apply goes through.
func TestApprovingALineUserPlanWithoutQueueApplyIsRefused(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	approval := filePlan(t, srv, lineUserOpAdd, u.ID, line.LineHashID)
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	decider := principal{Principal: rbac.Principal{ActorID: "decider", Scopes: []string{"network:apply", "network:plan", "vpncore:admin"}}}
	body := func(queue bool) string {
		return fmt.Sprintf(`{"approval_id":%q,"queue_apply":%t,"plan_sha256":%q}`, approval.ID, queue, planSHA)
	}

	rec := decideApproval(srv, "approve", body(false), decider)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "must queue their apply task") {
		t.Fatalf("approve without queue_apply: %d %s, want 400 naming the rule", rec.Code, rec.Body.String())
	}
	if stored, _ := srv.store.Approval(approval.ID); stored.Status != model.ApprovalPending || stored.ApprovedBy != "" {
		t.Fatalf("a refused approve-only changed the approval: %+v", stored)
	}
	if tasks := tasksFor(srv, approval.ID); len(tasks) != 0 {
		t.Fatalf("a refused approve-only queued %d task(s)", len(tasks))
	}
	if approves := lineUserAudit(srv, "network.singbox-lineuser.approve", approval.ID); len(approves) != 0 {
		t.Fatalf("a refused approve-only wrote an approve audit event: %+v", approves)
	}

	rec = decideApproval(srv, "approve", body(true), decider)
	if rec.Code != 200 {
		t.Fatalf("approve with queue_apply: %d %s", rec.Code, rec.Body.String())
	}
	if tasks := tasksFor(srv, approval.ID); len(tasks) != 1 {
		t.Fatalf("approve with queue_apply queued %d task(s), want 1", len(tasks))
	}
}

// An auto-approve rule with queue=false reaches the same decision path, so a
// line-user plan it matches stays pending for a decision that queues its
// apply. A rule with queue=true approves and queues it.
func TestAnApproveOnlyRuleLeavesALineUserPlanPending(t *testing.T) {
	for _, queue := range []bool{false, true} {
		t.Run(fmt.Sprintf("queue=%t", queue), func(t *testing.T) {
			srv := newLinemetaTestServer(t, mustOpenStore(t))
			line, u := seedLineUserFixture(t, srv)
			u.Bindings = nil
			if err := srv.putVpnUser(u); err != nil {
				t.Fatal(err)
			}
			srv.approvalAutoRules = []approvalAutoRule{{Name: "lineuser", Plugin: singBoxLineUserPlugin, Queue: queue}}
			approval := filePlan(t, srv, lineUserOpAdd, u.ID, line.LineHashID)
			stored, _ := srv.store.Approval(approval.ID)
			tasks := tasksFor(srv, approval.ID)
			if !queue {
				if stored.Status != model.ApprovalPending || len(tasks) != 0 {
					t.Fatalf("an approve-only rule left status %q and %d task(s), want pending and none", stored.Status, len(tasks))
				}
				return
			}
			if stored.Status != model.ApprovalApproved || stored.ApprovedBy != "policy:lineuser" || len(tasks) != 1 {
				t.Fatalf("a queueing rule left status %q by %q and %d task(s), want approved by policy:lineuser and one", stored.Status, stored.ApprovedBy, len(tasks))
			}
		})
	}
}

// From 86422a1 until dd75324 approving a line-user plan with queue_apply
// stored it approved with no task. Approving such an approval again must stay
// the no-op the approve path promises any decided approval, with or without
// queue_apply: no task, no audit event, no change to the approval or the
// user, so nothing can run a plan nobody re-reviewed.
func TestApprovingAStrandedLineUserApprovalChangesNothing(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	approval := filePlan(t, srv, lineUserOpAdd, u.ID, line.LineHashID)
	approval.Status = model.ApprovalApproved
	approval.ApprovedBy = "op-1"
	if err := srv.store.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	before, _ := srv.store.Approval(approval.ID)
	userBefore, _ := srv.getVpnUser(u.ID)
	tasksBefore := len(srv.store.Tasks())
	auditsBefore := len(srv.store.AuditEvents())
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	for _, queueApply := range []bool{true, false} {
		got, err := srv.approveApprovalCore(context.Background(), lineUserTestPrincipal(), before, queueApply, planSHA)
		if err != nil {
			t.Fatalf("approve an approved approval (queue_apply=%v): %v", queueApply, err)
		}
		if !reflect.DeepEqual(got, before) {
			t.Fatalf("approve returned a changed approval (queue_apply=%v):\n%+v\nwant\n%+v", queueApply, got, before)
		}
	}
	if after, _ := srv.store.Approval(approval.ID); !reflect.DeepEqual(after, before) {
		t.Fatalf("stored approval changed:\n%+v\nwant\n%+v", after, before)
	}
	if got := len(srv.store.Tasks()); got != tasksBefore {
		t.Fatalf("approving an approved approval queued %d task(s)", got-tasksBefore)
	}
	if got := len(srv.store.AuditEvents()); got != auditsBefore {
		t.Fatalf("approving an approved approval wrote %d audit event(s)", got-auditsBefore)
	}
	if userAfter, _ := srv.getVpnUser(u.ID); !reflect.DeepEqual(userAfter, userBefore) {
		t.Fatalf("user changed:\n%+v\nwant\n%+v", userAfter, userBefore)
	}
}

func mustOpenStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	return st
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

// The fork accepts a removal only as the JSON payload an add sends. The
// removal used to render a bare name, the argv this test pinned, and the
// fork answered every one with invalid_payload and exit 2.
func TestLineUserRemoveScriptSendsTheAddPayload(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	line, user := seedLineUserFixture(t, srv)
	remove := filePlan(t, srv, lineUserOpRemove, user.ID, line.LineHashID)
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(remove.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	payload, err := lineUserCredential(user, plan.Protocol, plan.UserName)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, _ := json.Marshal(payload)
	script := srv.applyScriptFor(remove)
	want := "\"$SB_BIN\" --json user del " + shellQuote(plan.Line) + " " + shellQuote(string(payloadJSON)) + "\n"
	if !strings.HasSuffix(script, want) {
		t.Fatalf("remove argv mismatch: want %q at the end of:\n%s", want, script)
	}
	if sha, _ := lineUserCredentialSHA(payload); sha != plan.CredentialSHA256 {
		t.Fatalf("the removal must send the payload its approval hashed: %s != %s", sha, plan.CredentialSHA256)
	}
	// The add for the same user and line sends the same bytes.
	addPayload := strings.Replace(want, " user del ", " user add ", 1)
	user.Bindings = nil
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	if add := srv.applyScriptFor(filePlan(t, srv, lineUserOpAdd, user.ID, line.LineHashID)); !strings.HasSuffix(add, addPayload) {
		t.Fatalf("the add must send the removal's payload:\n%s\nwant suffix %q", add, addPayload)
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
