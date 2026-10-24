package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestGroupPolicyGroupTargetsNeedAnUnrestrictedPrincipal pins the current
// disposition of finding E (2026-09-01 multi-operator audit). The first fix
// refused every node-restricted token from group policy writes; the follow-up
// decision (revised after the 2026-09-07 review) let a confined token define
// and delete policy for a group it fully reached at write time. Design 32
// reverses that follow-up decision: a stored group selector
// is expanded at plan time by whoever plans, the fleet-wide plan an
// unrestricted operator runs applies a confined author's group policy to
// every node the group resolves to then, and a selector-backed group grows on
// a tag or geo change with no write that could carry a reach check. So a
// group target, even one fully in reach today, needs an unrestricted
// principal, and a confined token targets explicit nodes instead
// (TestOutboundPolicyRestrictedPrincipalScope covers that half).
//
// Without the rule the confined upsert against the in-reach group returns
// 200, which is the regression this test exists to catch.
func TestGroupPolicyGroupTargetsNeedAnUnrestrictedPrincipal(t *testing.T) {
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

	upsert := func(token, groupID string) (int, string, string) {
		res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies",
			`{"scope_group_id":"`+groupID+`","enabled":true}`, token)
		defer res.Body.Close()
		body := new(bytes.Buffer)
		body.ReadFrom(res.Body)
		var out struct {
			ID string `json:"id"`
		}
		json.Unmarshal(body.Bytes(), &out)
		return res.StatusCode, out.ID, body.String()
	}
	del := func(token, policyID string) (int, string) {
		res := doBearerJSON(t, handler, http.MethodPost, "/api/group-policies/delete",
			`{"id":"`+policyID+`"}`, token)
		defer res.Body.Close()
		body := new(bytes.Buffer)
		body.ReadFrom(res.Body)
		return res.StatusCode, body.String()
	}
	// A refusal says why and what the caller can do instead.
	explains := func(t *testing.T, raw string) {
		t.Helper()
		for _, want := range []string{"outside your reach", "ask an operator with fleet scope"} {
			if !strings.Contains(strings.ToLower(raw), want) {
				t.Fatalf("refusal must say %q, got %s", want, raw)
			}
		}
	}

	for _, groupID := range []string{"g-in", "g-span"} {
		code, _, raw := upsert(confined, groupID)
		if code != http.StatusForbidden {
			t.Fatalf("confined token must be refused a group target (%s), got %d", groupID, code)
		}
		explains(t, raw)
		if !strings.Contains(strings.ToLower(raw), "name the nodes") {
			t.Fatalf("a refused group target must point at naming the nodes, got %s", raw)
		}
	}
	if policies := st.GroupPolicies(); len(policies) != 0 {
		t.Fatalf("the refused upserts must not land, found %d policies", len(policies))
	}

	// An unrestricted token with the same scopes proceeds, on either group.
	code, inID, _ := upsert(unrestricted, "g-in")
	if code != http.StatusOK {
		t.Fatalf("unrestricted token must define the in-reach group policy, got %d", code)
	}
	code, spanID, _ := upsert(unrestricted, "g-span")
	if code != http.StatusOK {
		t.Fatalf("unrestricted token must define the spanning policy, got %d", code)
	}

	// Delete follows the same rule.
	for _, policyID := range []string{inID, spanID} {
		code, raw := del(confined, policyID)
		if code != http.StatusForbidden {
			t.Fatalf("confined token must not delete a group policy, got %d", code)
		}
		explains(t, raw)
		if _, ok := st.GroupPolicy(policyID); !ok {
			t.Fatal("the refused delete must not land")
		}
		if code, _ := del(unrestricted, policyID); code != http.StatusOK {
			t.Fatalf("unrestricted token must delete the group policy, got %d", code)
		}
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
