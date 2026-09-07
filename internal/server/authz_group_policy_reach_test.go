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
