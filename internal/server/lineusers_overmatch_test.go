package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// sb user del removes every entry on the line that matches the payload's
// name or any of its credential fields. These tests pin the removals Lattice
// refuses because it can see another entry holding the same credential, and
// the flag a task result raises when the script's counts show it removed
// more than one entry anyway.

// setHubAInventory edits node-a's discovered hub-a line the way a fresh
// `sb --json list` report would, and drops the cached line read model.
func setHubAInventory(t *testing.T, srv *Server, mutate func(n *model.SingBoxNode)) {
	t.Helper()
	srv.singboxInvMu.Lock()
	inv := srv.singboxInv["node-a"]
	found := false
	for i := range inv.Nodes {
		if inv.Nodes[i].Name == "hub-a" {
			mutate(&inv.Nodes[i])
			found = true
		}
	}
	srv.singboxInv["node-a"] = inv
	srv.singboxInvMu.Unlock()
	if !found {
		t.Fatal("hub-a is not in node-a's inventory")
	}
	srv.invalidateLineReadModel()
}

func planRemoval(t *testing.T, srv *Server, userID string, line Line) error {
	t.Helper()
	_, err := srv.vpnUserLinePlan(lineUserTestPrincipal(),
		mustJSON(t, map[string]string{"user_id": userID, "line_hash_id": line.LineHashID}), lineUserOpRemove)
	return err
}

func TestARemovalIsRefusedWhenAnotherIdentityOnTheLineSharesTheCredential(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	line, u := seedLineUserFixture(t, srv)
	approval := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)

	// A migrated identity carries its legacy proxy user's uuid, and here
	// that uuid is also u's: two identities, one credential on the node.
	twin := VpnUser{
		ID: "vu_legacy-twin", Email: "twin@example.com", Enabled: true, MigratedFromProxyUser: "legacy-twin",
		Credentials: []VpnCredential{{Protocol: "vless", UUID: u.Credentials[0].UUID}},
		Bindings:    []LineBinding{{LineHashID: line.LineHashID, Enabled: true}},
	}
	if err := srv.putVpnUser(twin); err != nil {
		t.Fatal(err)
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), `identity "vu_legacy-twin"`) || !strings.Contains(err.Error(), "same uuid") ||
			!strings.Contains(err.Error(), "plan_update") {
			t.Fatalf("want the shared-credential refusal naming the twin and the remedy, got %v", err)
		}
	}
	before := len(srv.store.Approvals())
	refused(t, planRemoval(t, srv, u.ID, line))
	if len(srv.store.Approvals()) != before {
		t.Fatal("a refused removal filed an approval")
	}
	// The twin was bound after the first removal was filed: approval checks
	// again and refuses, and the script render fails closed.
	refused(t, approvePlan(t, srv, approval))
	if tasks := tasksFor(srv, approval.ID); len(tasks) != 0 {
		t.Fatalf("a refused approval queued %d task(s)", len(tasks))
	}
	if script := srv.applyScriptFor(approval); !strings.Contains(script, "vu_legacy-twin") || !strings.Contains(script, "exit 1") {
		t.Fatalf("the script render must fail closed:\n%s", script)
	}

	// An identity that only shares a protocol Lattice does not put on this
	// vless line is no obstacle, and neither is one on another line.
	twin.Credentials = []VpnCredential{{Protocol: "trojan", Password: "old-secret"}}
	if err := srv.putVpnUser(twin); err != nil {
		t.Fatal(err)
	}
	if err := approvePlan(t, srv, approval); err != nil {
		t.Fatalf("with the credential no longer shared the removal must approve: %v", err)
	}
}

func TestARemovalIsRefusedWhenTheLinesFirstEntryHoldsTheCredential(t *testing.T) {
	ownerShare := func(uuid string) string {
		return "vless://" + uuid + "@203.0.113.5:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=pk&fp=chrome#hub-a"
	}
	t.Run("Lattice never put the identity on the line", func(t *testing.T) {
		srv := newLinemetaTestServer(t, mustOpenStore(t))
		line, u := seedLineUserFixture(t, srv) // bound by a bind, no applied add
		setHubAInventory(t, srv, func(n *model.SingBoxNode) {
			n.ShareURL, n.UserKnown, n.UserCount = ownerShare(u.Credentials[0].UUID), true, 1
		})
		err := planRemoval(t, srv, u.ID, line)
		if err == nil || !strings.Contains(err.Error(), "first entry on line") || !strings.Contains(err.Error(), "not the one Lattice added") {
			t.Fatalf("a removal by a credential the line's own entry holds must be refused: %v", err)
		}
	})
	t.Run("the line holds more entries than Lattice's own", func(t *testing.T) {
		srv := newLinemetaTestServer(t, mustOpenStore(t))
		line, u := seedLineUserFixture(t, srv)
		u.Bindings = nil
		if err := srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
		applyLinePlan(t, srv, lineUserOpAdd, u.ID, line)
		setHubAInventory(t, srv, func(n *model.SingBoxNode) {
			n.ShareURL, n.UserKnown, n.UserCount = ownerShare(u.Credentials[0].UUID), true, 3
		})
		err := planRemoval(t, srv, u.ID, line)
		if err == nil || !strings.Contains(err.Error(), "holds 3 entries") {
			t.Fatalf("a first entry with the credential on a line of 3 must be refused: %v", err)
		}
	})
	t.Run("the only entry is Lattice's own", func(t *testing.T) {
		srv := newLinemetaTestServer(t, mustOpenStore(t))
		line, u := seedLineUserFixture(t, srv)
		u.Bindings = nil
		if err := srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
		applyLinePlan(t, srv, lineUserOpAdd, u.ID, line)
		setHubAInventory(t, srv, func(n *model.SingBoxNode) {
			n.ShareURL, n.UserKnown, n.UserCount = ownerShare(u.Credentials[0].UUID), true, 1
		})
		if err := planRemoval(t, srv, u.ID, line); err != nil {
			t.Fatalf("an add replaces matching entries and appends, so a single entry holding the credential is Lattice's: %v", err)
		}
	})
	t.Run("the first entry holds another credential", func(t *testing.T) {
		srv := newLinemetaTestServer(t, mustOpenStore(t))
		line, u := seedLineUserFixture(t, srv)
		setHubAInventory(t, srv, func(n *model.SingBoxNode) {
			n.ShareURL, n.UserKnown, n.UserCount = ownerShare("11111111-1111-4111-8111-111111111111"), true, 2
		})
		if err := planRemoval(t, srv, u.ID, line); err != nil {
			t.Fatalf("an owner entry with its own credential is no obstacle: %v", err)
		}
	})
}

// The script reports the line's user count before and after. A removal that
// took more than Lattice's own entry cannot be undone by then, so the result
// records it on the applied approval and in its own audit event.
func TestARemovalThatTookMoreThanOneEntryIsFlagged(t *testing.T) {
	cases := []struct {
		name          string
		stdout        string
		wantOvermatch bool
	}{
		{"one entry removed", `{"ok":true,"action":"del","line":"hub-a.json","user_count_before":2,"user_count_after":1}`, false},
		{"two entries removed", "restarting\n" + `{"ok":true,"action":"del","line":"hub-a.json","user_count_before":3,"user_count_after":1}`, true},
		{"an older script prints no counts", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLinemetaTestServer(t, mustOpenStore(t))
			line, u := seedLineUserFixture(t, srv)
			approval := filePlan(t, srv, lineUserOpRemove, u.ID, line.LineHashID)
			if err := approvePlan(t, srv, approval); err != nil {
				t.Fatal(err)
			}
			task := tasksFor(srv, approval.ID)[0]
			request := httptest.NewRequest("POST", "/api/agent/task-result", nil)
			if err := srv.handleApprovalTaskResult(request, task, model.TaskResult{TaskID: task.ID, NodeID: "node-a", Stdout: tc.stdout}); err != nil {
				t.Fatal(err)
			}
			stored, _ := srv.store.Approval(approval.ID)
			if stored.Status != model.ApprovalApplied {
				t.Fatalf("status %q, want applied: the node already ran the removal", stored.Status)
			}
			flags := lineUserAudit(srv, "vpnuser.line.overmatch", approval.ID)
			if !tc.wantOvermatch {
				if stored.Reason != "" || len(flags) != 0 {
					t.Fatalf("no over-match: reason %q, flags %+v", stored.Reason, flags)
				}
				return
			}
			if !strings.Contains(stored.Reason, "removed 2 entries") || !strings.Contains(stored.Reason, "1 other entries") {
				t.Fatalf("the applied approval must say what else went: %q", stored.Reason)
			}
			if len(flags) != 1 || flags[0].Metadata["user_count_before"] != "3" || flags[0].Metadata["user_count_after"] != "1" {
				t.Fatalf("over-match audit = %+v, want one event with the counts", flags)
			}
			applied := lineUserAudit(srv, "vpnuser.line.applied", approval.ID)
			if len(applied) != 1 || applied[0].Metadata["overmatch"] != "true" {
				t.Fatalf("applied audit = %+v, want it marked", applied)
			}
		})
	}
}

func TestLineUserOvermatchCountsAddsAndRemovals(t *testing.T) {
	cases := []struct {
		op            string
		before, after int
		want          bool
	}{
		{lineUserOpAdd, 1, 2, false},    // appended, replaced nothing
		{lineUserOpAdd, 2, 2, false},    // replaced one entry: Lattice's own or one other, cannot tell
		{lineUserOpAdd, 3, 2, true},     // replaced two
		{lineUserOpUpdate, 2, 2, false}, // replaced its own
		{lineUserOpUpdate, 3, 2, true},  // its own and another
		{lineUserOpRemove, 2, 1, false},
		{lineUserOpRemove, 1, 1, false}, // nothing matched
		{lineUserOpRemove, 4, 1, true},
	}
	for _, tc := range cases {
		got := lineUserOvermatch(lineUserPlan{Op: tc.op, Line: "hub-a", UserName: "u_x"}, tc.before, tc.after) != ""
		if got != tc.want {
			t.Fatalf("%s %d->%d: overmatch=%v, want %v", tc.op, tc.before, tc.after, got, tc.want)
		}
	}
}
