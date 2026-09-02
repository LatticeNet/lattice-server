package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// These four tests state the properties the operator surface should hold and
// currently does not. Each one is the same defect class the tree has now fixed
// twice: a handler authorizes the caller on the identifier it was given, then
// reads or writes a second identifier that was never checked.
//
// They are written as assertions of the intended behaviour, so each fails on
// the tree that has the defect and passes once it is closed. Nothing here is
// a fix.

// TestGroupUpsertRefusesMembersOutsideAllowlist covers POST /api/groups.
//
// handleGroupMembers was given requireReadableNodes for exactly this reason.
// The create/update sibling in the same file still gates on a flat
// requireScope("group:admin"), so a principal confined to one node can rewrite
// any group's explicit membership. Group membership drives
// netpolicy.ExpandGroupPolicies, so this decides which fleet firewall policy
// applies to nodes the caller cannot administer.
func TestGroupUpsertRefusesMembersOutsideAllowlist(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied"})
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"group:admin", "group:read"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"confined","slug":"confined","members":["node-b"]}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		body := new(bytes.Buffer)
		body.ReadFrom(res.Body)
		t.Fatalf("group:admin confined to node-a must not pin node-b into a group, got %d: %s",
			res.StatusCode, body.String())
	}
}

// TestGroupUpsertSelectorDoesNotResolveOverTheWholeFleet covers the read half
// of the same handler.
//
// handleGroupPreview was rewritten to resolve a caller-supplied selector over
// the readable subset, because resolving it over the whole fleet turned the
// endpoint into a query engine ("which nodes are in JP"). The create path
// resolves the same caller-supplied selector over every node in the store and
// echoes the result as resolved_members.
func TestGroupUpsertSelectorDoesNotResolveOverTheWholeFleet(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed", Role: "edge"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied", Role: "edge"})
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"group:admin", "group:read"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"probe","slug":"probe","selector":{"match_roles":["edge"]}}`, token)
	defer res.Body.Close()
	body := new(bytes.Buffer)
	body.ReadFrom(res.Body)
	if res.StatusCode == http.StatusOK && bytes.Contains(body.Bytes(), []byte("node-b")) {
		t.Fatalf("selector resolved over the whole fleet and disclosed node-b: %s", body.String())
	}
}

// TestGroupListDoesNotLeakExplicitMembers covers GET /api/groups.
//
// The listing filters ResolvedMembers, Rollup and ungrouped against the
// allowlist, and says so in a comment. groupView embeds model.Group, whose
// Members field carries json:"members", so encoding/json flattens the complete
// explicit membership of every group into the same response and around the
// filter.
func TestGroupListDoesNotLeakExplicitMembers(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied"})
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"mixed","slug":"mixed","members":["node-a","node-b"]}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("group create failed: %d", create.StatusCode)
	}

	token := createPAT(t, handler, cookies, csrf, []string{"group:read"}, []string{"node-a"})
	res := doBearerJSON(t, handler, http.MethodGet, "/api/groups", "", token)
	defer res.Body.Close()
	body := new(bytes.Buffer)
	body.ReadFrom(res.Body)
	if bytes.Contains(body.Bytes(), []byte("node-b")) {
		t.Fatalf("group:read confined to node-a received node-b in the group listing: %s", body.String())
	}
}

// TestApprovalRejectDoesNotDiscloseThePlanBeyondTheReadCheck covers the
// approval decision endpoints.
//
// approvalVisibleToPrincipal gates the LIST on every target plus the whole plan
// reach, which is what closed the wireguard mesh disclosure.
// requireApprovalDecisionScopes gates approve/reject/dismiss on approval.NodeID
// alone, and every one of them answers with toApprovalView, whose Plan field is
// the full plan text. Rejecting an approval a principal cannot list therefore
// hands back the mesh it was not allowed to read, and on an already-decided
// approval it mutates nothing, so it is a pure read.
func TestApprovalRejectDoesNotDiscloseThePlanBeyondTheReadCheck(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed", WireGuardIP: "10.66.0.1", WireGuardPublicKey: wgKey(1)})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied", WireGuardIP: "10.66.0.2", WireGuardPublicKey: wgKey(2)})
	cookies, csrf := loginSession(t, handler)

	plan := doJSON(t, handler, http.MethodPost, "/api/network/wireguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("wireguard plan failed: %d", plan.StatusCode)
	}
	var approval struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}

	// Confined to node-a: the same principal shape that is refused a direct
	// wireguard plan for node-b by TestPATServerAllowlistAppliesToWireGuardPlanBody.
	token := createPAT(t, handler, cookies, csrf,
		[]string{"network:apply", "wireguard:admin", "network:plan"}, []string{"node-a"})

	res := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/reject",
		`{"approval_id":"`+approval.ID+`"}`, token)
	defer res.Body.Close()
	body := new(bytes.Buffer)
	body.ReadFrom(res.Body)
	if res.StatusCode == http.StatusOK && bytes.Contains(body.Bytes(), []byte(wgKey(2))) {
		t.Fatalf("reject returned the mesh key of node-b, which this principal cannot read: %s", body.String())
	}
}

// TestEnrollTokenCannotJoinAGroupWithoutGroupAdmin covers
// POST /api/nodes/enroll-token.
//
// The route is gated on node:admin. group_ids on the request body appends the
// freshly enrolled node to each named group's explicit Members, which is a
// group:admin operation performed without group:admin, and which grants the
// caller's own node whatever policy that group carries.
func TestEnrollTokenCannotJoinAGroupWithoutGroupAdmin(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"trusted","slug":"trusted"}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("group create failed: %d", create.StatusCode)
	}
	var group struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&group); err != nil {
		t.Fatal(err)
	}

	token := createPAT(t, handler, cookies, csrf, []string{"node:admin"}, nil)
	res := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"name":"joiner","group_ids":["`+group.ID+`"]}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		body := new(bytes.Buffer)
		body.ReadFrom(res.Body)
		t.Fatalf("node:admin without group:admin must not write group membership, got %d: %s",
			res.StatusCode, body.String())
	}
}

// TestRerunNodeAuthorizesBeforeMembership pins Finding C of the 2026-09-01
// multi-operator audit: /api/tasks/rerun-node checked task-target membership
// (400) before the scope check, so a caller without task:run on a node could
// tell a foreign task's target set apart from a generic refusal and probe task
// ids. Authorization now runs first, so a caller lacking the node sees the
// same refusal whether or not the task targets it.
func TestRerunNodeAuthorizesBeforeMembership(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied"})
	if err := st.CreateTask(model.Task{
		ID: "task-foreign", Targets: []string{"node-b"}, Interpreter: "sh",
		Script: "echo hi", Status: model.TaskFinished,
	}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	// Token confined to node-a: no scope on node-b, where the task lives.
	token := createPAT(t, handler, cookies, csrf, []string{"task:run"}, []string{"node-a"})

	// Probe with a node the caller does NOT hold and that the task does NOT
	// target. Old order: taskTargetContains is false, so 400 "not a target"
	// fired before any scope check, distinguishing this from an in-target node
	// (which fell through to 403). New order: the scope check runs first and
	// refuses with 403 regardless of membership, so the two are indistinguishable.
	nonTarget := doBearerJSON(t, handler, http.MethodPost, "/api/tasks/rerun-node",
		`{"id":"task-foreign","node_id":"node-c"}`, token)
	nonTarget.Body.Close()
	if nonTarget.StatusCode != http.StatusForbidden {
		t.Fatalf("an unauthorized non-target node must 403, not leak membership via 400; got %d", nonTarget.StatusCode)
	}
	// An in-target but unauthorized node is also 403: same answer, no oracle.
	inTarget := doBearerJSON(t, handler, http.MethodPost, "/api/tasks/rerun-node",
		`{"id":"task-foreign","node_id":"node-b"}`, token)
	inTarget.Body.Close()
	if inTarget.StatusCode != http.StatusForbidden {
		t.Fatalf("an unauthorized in-target node must 403, got %d", inTarget.StatusCode)
	}
}

// TestFleetWideWritesRefuseConfinedTokens pins findings B, D, and E of the
// 2026-09-01 multi-operator audit: writes whose blast radius is the whole
// fleet carry no node id, so rbac.Allows never consults the allowlist, and a
// node-restricted token reached past its confinement. Every such write now
// refuses a confined principal BEFORE decoding the body: the confined token
// sees 403 where an unrestricted one proceeds to ordinary validation.
func TestFleetWideWritesRefuseConfinedTokens(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	cookies, csrf := loginSession(t, handler)
	scopes := []string{"notify:send", "oidc:admin", "netpolicy:admin"}
	confined := createPAT(t, handler, cookies, csrf, scopes, []string{"node-a"})
	unrestricted := createPAT(t, handler, cookies, csrf, scopes, nil)

	endpoints := []string{
		"/api/notify/channels",
		"/api/notify/channels/delete",
		"/api/notify/rules",
		"/api/notify/rules/delete",
		"/api/auth/oidc/providers",
		"/api/auth/oidc/providers/delete",
		"/api/group-policies",
		"/api/group-policies/delete",
	}
	for _, path := range endpoints {
		res := doBearerJSON(t, handler, http.MethodPost, path, `{}`, confined)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: confined token must be refused with 403, got %d", path, res.StatusCode)
		}
		res = doBearerJSON(t, handler, http.MethodPost, path, `{}`, unrestricted)
		res.Body.Close()
		if res.StatusCode == http.StatusForbidden {
			t.Errorf("%s: unrestricted token must pass the gate (any non-403), got 403", path)
		}
	}
}
