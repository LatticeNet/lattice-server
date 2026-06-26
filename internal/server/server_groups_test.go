package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestGroupCycleOK(t *testing.T) {
	// a -> b -> c (no cycle); making c's parent a would cycle.
	base := map[string]model.Group{
		"a": {ID: "a", ParentID: ""},
		"b": {ID: "b", ParentID: "a"},
		"c": {ID: "c", ParentID: "b"},
	}
	if err := groupCycleOK("c", base); err != nil {
		t.Fatalf("acyclic chain rejected: %v", err)
	}
	cyclic := map[string]model.Group{
		"a": {ID: "a", ParentID: "c"},
		"b": {ID: "b", ParentID: "a"},
		"c": {ID: "c", ParentID: "b"},
	}
	if err := groupCycleOK("c", cyclic); err == nil {
		t.Fatal("expected cycle to be rejected")
	}
	// Missing parent is an error.
	if err := groupCycleOK("x", map[string]model.Group{"x": {ID: "x", ParentID: "ghost"}}); err == nil {
		t.Fatal("expected missing parent to be rejected")
	}
}

func TestGroupCycleDepthBound(t *testing.T) {
	m := map[string]model.Group{}
	prev := ""
	// Build a chain longer than groupMaxNestDepth.
	for i := 0; i <= groupMaxNestDepth+2; i++ {
		idStr := string(rune('a' + i))
		m[idStr] = model.Group{ID: idStr, ParentID: prev}
		prev = idStr
	}
	leaf := string(rune('a' + groupMaxNestDepth + 2))
	if err := groupCycleOK(leaf, m); err == nil {
		t.Fatalf("expected depth bound (%d) to reject a longer chain", groupMaxNestDepth)
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"prod":           "prod",
		"US East":        "us-east",
		"  edge--node  ": "edge-node",
		"组长":             "", // non-ascii collapses to empty
		"a.b_c/d":        "a-b-c-d",
		"---trim---":     "trim",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDedupeExistingNodes(t *testing.T) {
	byNode := map[string]model.Node{"n1": {ID: "n1"}, "n2": {ID: "n2"}}
	got := dedupeExistingNodes([]string{"n2", "n1", "n1", " ", "ghost", "n2"}, byNode)
	want := []string{"n1", "n2"} // deduped, sorted, ghost dropped
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dedupeExistingNodes = %v, want %v", got, want)
	}
}

func TestNormalizeGroupSelector(t *testing.T) {
	if normalizeGroupSelector(nil) != nil {
		t.Fatal("nil selector should stay nil")
	}
	empty := &model.GroupSelector{MatchRoles: []string{"  "}}
	if normalizeGroupSelector(empty) != nil {
		t.Fatal("selector with only blank entries should normalize to nil")
	}
	sel := normalizeGroupSelector(&model.GroupSelector{MatchTagsAny: []string{"a", " ", "b"}})
	if sel == nil || len(sel.MatchTagsAny) != 2 {
		t.Fatalf("expected 2 trimmed tags, got %+v", sel)
	}
}

func TestRollupFor(t *testing.T) {
	byID := map[string]model.Node{
		"n1": {ID: "n1", Online: true},
		"n2": {ID: "n2", Online: false},
		"n3": {ID: "n3", Online: false, Disabled: true},
	}
	r, resolved := rollupFor([]string{"n1", "n2", "n3", "ghost"}, byID)
	if r.Total != 3 || r.Online != 1 || r.Offline != 2 || r.Disabled != 1 {
		t.Fatalf("unexpected rollup: %+v", r)
	}
	if len(resolved) != 3 {
		t.Fatalf("expected ghost dropped from resolved, got %v", resolved)
	}
}

// --- Slice 4 HTTP-level tests -------------------------------------------------

// enrollTestNode posts an enroll-token request and returns the new node id.
func enrollTestNode(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, body string) string {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token", body, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll %q failed: %d", body, res.StatusCode)
	}
	var out struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	if out.NodeID == "" {
		t.Fatal("enroll returned an empty node id")
	}
	return out.NodeID
}

func listTestGroups(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) []groupView {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/groups", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list groups failed: %d", res.StatusCode)
	}
	var out struct {
		Groups []groupView `json:"groups"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode groups: %v", err)
	}
	return out.Groups
}

func sliceHasString(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

// TestEnrollNodeAssignsGroups verifies that enrolling with group_ids appends the
// new node into each named group's canonical membership and that the node then
// resolves into those groups. An unknown group id rejects the whole enroll.
func TestEnrollNodeAssignsGroups(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	// Create an empty group.
	res := doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Edge","slug":"edge-enroll"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create group failed: %d", res.StatusCode)
	}
	var g groupView
	if err := json.NewDecoder(res.Body).Decode(&g); err != nil {
		t.Fatalf("decode group: %v", err)
	}
	res.Body.Close()

	// Enroll a node assigned to the group at enrollment.
	nodeID := enrollTestNode(t, handler, cookies, csrf,
		`{"name":"edge-1","group_ids":["`+g.ID+`"]}`)

	groups := listTestGroups(t, handler, cookies, csrf)
	var found *groupView
	for i := range groups {
		if groups[i].ID == g.ID {
			found = &groups[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("group %q missing from list", g.ID)
	}
	if !sliceHasString(found.Members, nodeID) {
		t.Fatalf("enrolled node %q not in canonical members %v", nodeID, found.Members)
	}
	if !sliceHasString(found.ResolvedMembers, nodeID) {
		t.Fatalf("enrolled node %q not resolved into group %v", nodeID, found.ResolvedMembers)
	}

	// An unknown group id rejects the whole enroll with 400 (no orphan node).
	bad := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"name":"orphan","group_ids":["grp_missing"]}`, cookies, csrf)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown group id, got %d", bad.StatusCode)
	}
	bad.Body.Close()
}

// TestGroupLeaderRequiresMember verifies leader_id validation: a leader must be
// an explicit member of the group, otherwise the upsert is rejected with 400.
func TestGroupLeaderRequiresMember(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	n1 := enrollTestNode(t, handler, cookies, csrf, `{"name":"n1"}`)
	n2 := enrollTestNode(t, handler, cookies, csrf, `{"name":"n2"}`)

	// Create a group whose only explicit member is n1.
	res := doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"name":"Leaders","slug":"leaders","members":["`+n1+`"]}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create group failed: %d", res.StatusCode)
	}
	var g groupView
	if err := json.NewDecoder(res.Body).Decode(&g); err != nil {
		t.Fatalf("decode group: %v", err)
	}
	res.Body.Close()

	// leader_id pointing at a non-member (n2) must be rejected.
	bad := doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"id":"`+g.ID+`","name":"Leaders","slug":"leaders","members":["`+n1+`"],"leader_id":"`+n2+`"}`,
		cookies, csrf)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-member leader, got %d", bad.StatusCode)
	}
	bad.Body.Close()

	// leader_id pointing at an explicit member (n1) is accepted and persisted.
	ok := doJSON(t, handler, http.MethodPost, "/api/groups",
		`{"id":"`+g.ID+`","name":"Leaders","slug":"leaders","members":["`+n1+`"],"leader_id":"`+n1+`"}`,
		cookies, csrf)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("expected member leader to be accepted, got %d", ok.StatusCode)
	}
	var saved groupView
	if err := json.NewDecoder(ok.Body).Decode(&saved); err != nil {
		t.Fatalf("decode saved group: %v", err)
	}
	ok.Body.Close()
	if saved.LeaderID != n1 {
		t.Fatalf("leader_id not persisted: got %q want %q", saved.LeaderID, n1)
	}
}
