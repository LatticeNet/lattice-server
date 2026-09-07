package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestGroupPolicyWritesConfinedToGroupReach pins the follow-up disposition of
// finding E (2026-09-01 multi-operator audit). The first fix refused every
// node-restricted token from group policy writes, the same rule the no-node
// objects (capability gates, SSO providers, notify routing) use. But a group
// policy names its blast radius, the members of its scope group, so the
// confinement model can do better than a ban: a confined token may define and
// delete policy for a group it fully reaches, and is refused the moment the
// group resolves to any node outside its allowlist. This is the reach rule the
// enroll-time group join and group membership edits already apply.
//
// Without the reach check the confined upsert against the spanning group
// returns 200 and the policy lands, which is the regression this test exists
// to catch.
func TestGroupPolicyWritesConfinedToGroupReach(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied"})
	if err := st.UpsertGroup(model.Group{ID: "g-in", Name: "in-reach", Slug: "in-reach", Members: []string{"node-a"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "g-span", Name: "spanning", Slug: "spanning", Members: []string{"node-a", "node-b"}}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	confined := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, []string{"node-a"})
	unrestricted := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, nil)

	upsert := func(token, groupID string) (int, string) {
		res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies",
			`{"scope_group_id":"`+groupID+`","enabled":true}`, token)
		defer res.Body.Close()
		body := new(bytes.Buffer)
		body.ReadFrom(res.Body)
		var out struct {
			ID string `json:"id"`
		}
		json.Unmarshal(body.Bytes(), &out)
		return res.StatusCode, out.ID
	}
	del := func(token, policyID string) int {
		res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies/delete",
			`{"id":"`+policyID+`"}`, token)
		res.Body.Close()
		return res.StatusCode
	}

	// A confined token writes freely within its reach.
	code, inReachID := upsert(confined, "g-in")
	if code != http.StatusOK {
		t.Fatalf("confined token must define policy for a group it fully reaches, got %d", code)
	}

	// The same token is refused the moment the group spans past the allowlist.
	if code, _ := upsert(confined, "g-span"); code != http.StatusForbidden {
		t.Fatalf("confined token must be refused on a group spanning node-b, got %d", code)
	}
	if policies := st.GroupPolicies(); len(policies) != 1 {
		t.Fatalf("the refused upsert must not land, found %d policies", len(policies))
	}

	// An unrestricted token with the same scopes proceeds.
	code, spanID := upsert(unrestricted, "g-span")
	if code != http.StatusOK {
		t.Fatalf("unrestricted token must define the spanning policy, got %d", code)
	}

	// Delete follows the same reach rule.
	if code := del(confined, spanID); code != http.StatusForbidden {
		t.Fatalf("confined token must not delete policy for a group spanning node-b, got %d", code)
	}
	if _, ok := st.GroupPolicy(spanID); !ok {
		t.Fatal("the refused delete must not land")
	}
	if code := del(confined, inReachID); code != http.StatusOK {
		t.Fatalf("confined token must delete its in-reach policy, got %d", code)
	}
	if code := del(unrestricted, spanID); code != http.StatusOK {
		t.Fatalf("unrestricted token must delete the spanning policy, got %d", code)
	}
}

// TestGroupPolicyUpdateChecksThePriorScopeGroup pins the takeover the first
// reach check left open (security review, 2026-09-07). The check read only the
// scope group in the request body, so an update never consulted the policy it
// was about to overwrite: a confined caller could name a policy whose group
// spans nodes outside its allowlist, re-point it at a group inside, and strip
// policy from nodes it cannot reach while every check passed. Drop the prior
// half of the union in server_group_policy.go and the update below returns 200
// and the stored scope moves to g-in.
func TestGroupPolicyUpdateChecksThePriorScopeGroup(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	st.UpsertNode(model.Node{ID: "node-b", Name: "denied"})
	if err := st.UpsertGroup(model.Group{ID: "g-in", Name: "in-reach", Slug: "in-reach", Members: []string{"node-a"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroup(model.Group{ID: "g-span", Name: "spanning", Slug: "spanning", Members: []string{"node-a", "node-b"}}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	confined := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, []string{"node-a"})
	unrestricted := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, nil)

	// An unrestricted token defines policy over the spanning group.
	res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"scope_group_id":"g-span","enabled":true}`, unrestricted)
	body := new(bytes.Buffer)
	body.ReadFrom(res.Body)
	res.Body.Close()
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(body.Bytes(), &created)
	if res.StatusCode != http.StatusOK || created.ID == "" {
		t.Fatalf("setup: unrestricted upsert got %d", res.StatusCode)
	}

	// The confined token tries to take that policy over and narrow it to a
	// group it does reach. The nodes losing coverage are the ones it cannot see.
	takeover := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"id":"`+created.ID+`","scope_group_id":"g-in","enabled":true}`, confined)
	takeover.Body.Close()
	if takeover.StatusCode != http.StatusForbidden {
		t.Fatalf("confined token must not re-point a policy whose prior group spans node-b, got %d", takeover.StatusCode)
	}
	gp, ok := st.GroupPolicy(created.ID)
	if !ok {
		t.Fatal("the refused update must leave the policy in place")
	}
	if gp.ScopeGroupID != "g-span" {
		t.Fatalf("the refused update must not move the scope group, got %q", gp.ScopeGroupID)
	}
}

// TestGroupPolicyEmptyScopeGroupRefusesConfinedToken pins the second half of
// the same review finding: requireReadableNodes passes an empty node set
// vacuously, so a group resolving to no nodes was a hole a confined caller
// could write through, and the group can gain members outside the allowlist
// later. An unrestricted caller keeps the empty case.
func TestGroupPolicyEmptyScopeGroupRefusesConfinedToken(t *testing.T) {
	handler, st := newTestServer(t)
	st.UpsertNode(model.Node{ID: "node-a", Name: "allowed"})
	if err := st.UpsertGroup(model.Group{ID: "g-empty", Name: "empty", Slug: "empty"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	confined := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, []string{"node-a"})
	unrestricted := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin", "netpolicy:read"}, nil)

	res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"scope_group_id":"g-empty","enabled":true}`, confined)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("confined token must be refused on a group resolving to no nodes, got %d", res.StatusCode)
	}
	if policies := st.GroupPolicies(); len(policies) != 0 {
		t.Fatalf("the refused upsert must not land, found %d policies", len(policies))
	}

	ok := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies",
		`{"scope_group_id":"g-empty","enabled":true}`, unrestricted)
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("unrestricted token must still define policy for an empty group, got %d", ok.StatusCode)
	}
}
