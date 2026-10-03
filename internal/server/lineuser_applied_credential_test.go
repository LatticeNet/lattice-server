package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// r1-critic X-5: the line-user task result owns a binding's applied
// credential for every op, across both designs: the per-identity link's
// lines (identity-sub P3) and the suspension reconciler's suspend and resume
// (adopted-suspend P4). One table, every op, from every starting binding.
func TestReconcileLineUserBindingOwnsTheAppliedCredential(t *testing.T) {
	const line, other = "line_a", "line_b"
	const oldSHA, newSHA = "1111111111111111111111111111111111111111111111111111111111111111", "2222222222222222222222222222222222222222222222222222222222222222"
	applied := LineBinding{LineHashID: line, Enabled: true, AppliedCredentialSHA256: oldSHA}
	bindOnly := LineBinding{LineHashID: line, Enabled: true}
	disabled := LineBinding{LineHashID: line, Enabled: false, AppliedCredentialSHA256: oldSHA}
	for _, tc := range []struct {
		name    string
		op      string
		start   *LineBinding
		present bool
		enabled bool
		hash    string
		changed bool
	}{
		{"add to an unbound identity", lineUserOpAdd, nil, true, true, newSHA, true},
		{"add over a bind-only binding", lineUserOpAdd, &bindOnly, true, true, newSHA, true},
		{"update after a rotation", lineUserOpUpdate, &applied, true, true, newSHA, true},
		{"update with the same credential", lineUserOpUpdate, &LineBinding{LineHashID: line, Enabled: true, AppliedCredentialSHA256: newSHA}, true, true, newSHA, false},
		{"update re-enables a disabled binding", lineUserOpUpdate, &disabled, true, true, newSHA, true},
		{"resume puts the credential back", lineUserOpResume, &LineBinding{LineHashID: line, Enabled: true}, true, true, newSHA, true},
		{"resume of an unbound identity binds it", lineUserOpResume, nil, true, true, newSHA, true},
		{"suspend keeps the binding and clears the credential", lineUserOpSuspend, &applied, true, true, "", true},
		{"suspend keeps a disabled binding disabled", lineUserOpSuspend, &disabled, true, false, "", true},
		{"suspend of an unbound identity binds nothing", lineUserOpSuspend, nil, false, false, "", false},
		{"remove drops the binding and its credential", lineUserOpRemove, &applied, false, false, "", true},
		{"remove of an unbound identity changes nothing", lineUserOpRemove, nil, false, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := VpnUser{ID: "vpnuser_x", Bindings: []LineBinding{{LineHashID: other, Enabled: true, AppliedCredentialSHA256: oldSHA}}}
			if tc.start != nil {
				u.Bindings = append(u.Bindings, *tc.start)
			}
			before := append([]LineBinding(nil), u.Bindings...)
			got, changed, err := reconcileLineUserBinding(u, lineUserPlan{Op: tc.op, LineHashID: line, CredentialSHA256: newSHA})
			if err != nil {
				t.Fatal(err)
			}
			if changed != tc.changed {
				t.Fatalf("changed = %v, want %v", changed, tc.changed)
			}
			var found *LineBinding
			for i := range got.Bindings {
				if got.Bindings[i].LineHashID == line {
					found = &got.Bindings[i]
				}
				if got.Bindings[i].LineHashID == other && got.Bindings[i].AppliedCredentialSHA256 != oldSHA {
					t.Fatalf("another line's binding changed: %+v", got.Bindings[i])
				}
			}
			if (found != nil) != tc.present {
				t.Fatalf("binding present = %v, want %v: %+v", found != nil, tc.present, got.Bindings)
			}
			if found != nil && (found.Enabled != tc.enabled || found.AppliedCredentialSHA256 != tc.hash) {
				t.Fatalf("binding = %+v, want enabled=%v hash=%q", *found, tc.enabled, tc.hash)
			}
			for i := range before {
				if i < len(u.Bindings) && u.Bindings[i] != before[i] {
					t.Fatal("reconcile must not edit the caller's bindings in place")
				}
			}
		})
	}
	if _, _, err := reconcileLineUserBinding(VpnUser{}, lineUserPlan{Op: "park"}); err == nil {
		t.Fatal("an unknown op must be refused")
	}
}

// The same lifecycle through the real path on an adopted line: an applied
// add records the reviewed credential, a rotation makes the node stale, an
// applied update makes it current again, the reconciler's suspend clears it
// and its resume puts the rotated credential back, and an applied remove
// takes the binding with it. bind alone proves nothing. The identity view
// reports each state.
func TestAppliedCredentialFollowsTheNode(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	u.Bindings = nil
	if err := srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	state := func() (LineBinding, string) {
		t.Helper()
		current, _ := srv.getVpnUser(u.ID)
		views := srv.vpnUserUsageViews([]VpnUser{current}, srv.now())
		for i, b := range current.Bindings {
			if b.LineHashID == line.LineHashID {
				if views[0].Bindings[i].LineHashID != b.LineHashID {
					t.Fatalf("view binding order: %+v", views[0].Bindings)
				}
				return b, views[0].Bindings[i].Credential
			}
		}
		return LineBinding{}, ""
	}
	planSHA := func(a model.Approval) string {
		var plan lineUserPlan
		if err := json.Unmarshal([]byte(a.Plan), &plan); err != nil {
			t.Fatal(err)
		}
		return plan.CredentialSHA256
	}

	add := filePlan(t, srv, lineUserOpAdd, u.ID, line.LineHashID)
	applyLinePlanResult(t, srv, add, line)
	if b, cred := state(); b.AppliedCredentialSHA256 != planSHA(add) || cred != lineCredentialCurrent {
		t.Fatalf("after add: %+v %s", b, cred)
	}

	if _, err := srv.vpnUserRotateCredential(lineUserTestPrincipal(), mustJSON(t, map[string]string{"user_id": u.ID, "protocol": "vless"})); err != nil {
		t.Fatal(err)
	}
	if b, cred := state(); b.AppliedCredentialSHA256 != planSHA(add) || cred != lineCredentialStale {
		t.Fatalf("after rotate: %+v %s", b, cred)
	}

	update := filePlan(t, srv, lineUserOpUpdate, u.ID, line.LineHashID)
	applyLinePlanResult(t, srv, update, line)
	if b, cred := state(); b.AppliedCredentialSHA256 != planSHA(update) || planSHA(update) == planSHA(add) || cred != lineCredentialCurrent {
		t.Fatalf("after update: %+v %s", b, cred)
	}

	// The reconciler's suspend and resume reach the binding through the same
	// owner the result path uses.
	reconcileStored := func(op, sha string) {
		t.Helper()
		current, _ := srv.getVpnUser(u.ID)
		next, _, err := reconcileLineUserBinding(current, lineUserPlan{Op: op, LineHashID: line.LineHashID, CredentialSHA256: sha})
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.putVpnUser(next); err != nil {
			t.Fatal(err)
		}
	}
	reconcileStored(lineUserOpSuspend, planSHA(update))
	if b, cred := state(); !b.Enabled || b.AppliedCredentialSHA256 != "" || cred != lineCredentialNone {
		t.Fatalf("after suspend: %+v %s", b, cred)
	}
	if _, err := srv.vpnUserRotateCredential(lineUserTestPrincipal(), mustJSON(t, map[string]string{"user_id": u.ID, "protocol": "vless"})); err != nil {
		t.Fatal(err)
	}
	rotated, _ := srv.getVpnUser(u.ID)
	payload, err := lineUserCredential(rotated, line.Type, userLineName(u.ID, line.LineUUID))
	if err != nil {
		t.Fatal(err)
	}
	resumeSHA, _ := lineUserCredentialSHA(payload)
	reconcileStored(lineUserOpResume, resumeSHA)
	if b, cred := state(); b.AppliedCredentialSHA256 != resumeSHA || cred != lineCredentialCurrent {
		t.Fatalf("after a resume that applied the credential rotated while suspended: %+v %s", b, cred)
	}

	remove := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
	request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
	if err := approvePlan(t, srv, remove); err != nil {
		t.Fatal(err)
	}
	task := tasksFor(srv, remove.ID)[0]
	if err := srv.handleApprovalTaskResult(request, task, model.TaskResult{TaskID: task.ID, NodeID: line.NodeID}); err != nil {
		t.Fatal(err)
	}
	if b, _ := state(); b.LineHashID != "" {
		t.Fatalf("after remove the binding must be gone: %+v", b)
	}

	if _, err := srv.vpnUserBind(mustJSON(t, map[string]string{"user_id": u.ID, "line_hash_id": line.LineHashID})); err != nil {
		t.Fatal(err)
	}
	if b, cred := state(); !b.Enabled || b.AppliedCredentialSHA256 != "" || cred != lineCredentialNone {
		t.Fatalf("a bind-only binding proves nothing: %+v %s", b, cred)
	}
}

// A managed line's applied plan records the credential the managed render put
// on the node.
func TestManagedApplyRecordsTheAppliedCredential(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, user := seedManagedLineUserFixture(t, srv)
	add := filePlan(t, srv, lineUserOpAdd, user.ID, line.LineHashID)
	if err := srv.handleLineUserTaskResult(httptest.NewRequest("POST", "/api/agent/task-result", nil), add, model.Task{ID: "managed-add"}, model.TaskResult{}); err != nil {
		t.Fatal(err)
	}
	stored, _ := srv.getVpnUser(user.ID)
	var plan lineUserPlan
	_ = json.Unmarshal([]byte(add.Plan), &plan)
	if len(stored.Bindings) != 1 || stored.Bindings[0].AppliedCredentialSHA256 != plan.CredentialSHA256 || plan.CredentialSHA256 == "" {
		t.Fatalf("managed binding = %+v, plan credential %q", stored.Bindings, plan.CredentialSHA256)
	}
	_, lines := srv.lineReadModel()
	if got := lineBindingCredentialState(stored, stored.Bindings[0], lines[line.LineHashID], true); got != lineCredentialCurrent {
		t.Fatalf("managed credential state = %s", got)
	}
}

// Bindings made before the field existed are filled once from approval
// history, at boot: the last applied plan for the pair decides. A removal
// leaves the binding empty, a pair no plan touched stays empty, and a later
// run changes nothing even if history moved, because the result path owns the
// field from then on.
func TestAppliedCredentialBackfillReadsApprovalHistoryOnce(t *testing.T) {
	st := mustOpenStore(t)
	const line = "line_backfill"
	seed := func(u VpnUser) {
		t.Helper()
		public, private := splitVpnUserRecord(u)
		if err := st.PutVpnUserRecord(public, private); err != nil {
			t.Fatal(err)
		}
	}
	identity := func(email, uuid string) VpnUser {
		return VpnUser{ID: id.New("vpnuser"), Email: email, Enabled: true,
			Credentials: []VpnCredential{{Protocol: "vless", UUID: uuid}}, Bindings: []LineBinding{{LineHashID: line, Enabled: true}}}
	}
	updated := identity("updated@example.com", "6a1b7c2d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
	removed := identity("removed@example.com", "7a1b7c2d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
	untouched := identity("bind@example.com", "8a1b7c2d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
	for _, u := range []VpnUser{updated, removed, untouched} {
		seed(u)
	}
	put := func(plan lineUserPlan) {
		t.Helper()
		raw, _ := json.Marshal(plan)
		if err := st.UpsertApproval(model.Approval{ID: id.New("approval"), Plugin: singBoxLineUserPlugin, Status: model.ApprovalApplied,
			Plan: string(raw), RequestSHA256: lineUserRequestSHA(plan.UserID, plan.LineHashID)}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond) // UpsertApproval stamps UpdatedAt, which orders history
	}
	const firstSHA, updateSHA, removeSHA = "5555555555555555555555555555555555555555555555555555555555555555",
		"3333333333333333333333333333333333333333333333333333333333333333", "4444444444444444444444444444444444444444444444444444444444444444"
	put(lineUserPlan{Op: lineUserOpAdd, UserID: updated.ID, LineHashID: line, CredentialSHA256: firstSHA})
	put(lineUserPlan{Op: lineUserOpUpdate, UserID: updated.ID, LineHashID: line, CredentialSHA256: updateSHA})
	put(lineUserPlan{Op: lineUserOpAdd, UserID: removed.ID, LineHashID: line, CredentialSHA256: removeSHA})
	put(lineUserPlan{Op: lineUserOpRemove, UserID: removed.ID, LineHashID: line, CredentialSHA256: removeSHA})

	srv := newLinemetaTestServer(t, st)
	applied := func(userID string) string {
		got, _ := srv.getVpnUser(userID)
		for _, b := range got.Bindings {
			if b.LineHashID == line {
				return b.AppliedCredentialSHA256
			}
		}
		return "missing"
	}
	if got := applied(updated.ID); got != updateSHA {
		t.Fatalf("the last applied plan, an update, must fill the binding: %q", got)
	}
	if got := applied(removed.ID); got != "" {
		t.Fatalf("a removal last must leave the binding empty: %q", got)
	}
	if got := applied(untouched.ID); got != "" {
		t.Fatalf("a pair no plan touched must stay empty: %q", got)
	}
	put(lineUserPlan{Op: lineUserOpAdd, UserID: untouched.ID, LineHashID: line, CredentialSHA256: updateSHA})
	if err := srv.backfillLineUserAppliedCredentials(); err != nil {
		t.Fatal(err)
	}
	if got := applied(untouched.ID); got != "" {
		t.Fatalf("the backfill must run once: %q", got)
	}
}

// The store refuses an applied credential that is not a SHA-256 in lower hex,
// so nothing but a hash can ever be kept there.
func TestStoreRefusesAnAppliedCredentialThatIsNotAHash(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	u := VpnUser{ID: "vpnuser_hash", Email: "hash@example.com", Enabled: true, Credentials: []VpnCredential{},
		Bindings: []LineBinding{{LineHashID: "line_a", Enabled: true, AppliedCredentialSHA256: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}}}
	if err := srv.putVpnUser(u); err == nil || !strings.Contains(err.Error(), "applied credential hash") {
		t.Fatalf("a credential where the hash goes must be refused: %v", err)
	}
	raw, _ := json.Marshal(toVpnUserView(VpnUser{Bindings: []LineBinding{{LineHashID: "line_a", AppliedCredentialSHA256: strings.Repeat("a", 64)}}}))
	if strings.Contains(string(raw), strings.Repeat("a", 64)) {
		t.Fatalf("views must not carry the applied hash: %s", raw)
	}
}
