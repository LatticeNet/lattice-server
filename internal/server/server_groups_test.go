package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
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

// The rollup counts each member once, under the status the same response shows
// on that member's own row. Counting the raw Online bool instead put a disabled
// node that was still beating into disabled and online at once, and trusted a
// flag the liveness sweep had not caught up with yet.
func TestRollupForCountsEachNodeOnceUnderItsDerivedStatus(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	enrolled := now.Add(-48 * time.Hour)
	fresh := now.Add(-3 * time.Second)
	nodes := []model.Node{
		{ID: "n1", Online: true, LastSeen: fresh, OnlineSince: now.Add(-time.Hour), CreatedAt: enrolled},
		// Disabled, and the agent has not noticed: disabled only, never online.
		{ID: "n2", Online: true, LastSeen: fresh, Disabled: true, DisabledAt: now.Add(-time.Hour), CreatedAt: enrolled},
		// The beat went stale before the liveness sweep flipped Online.
		{ID: "n3", Online: true, LastSeen: now.Add(-nodeOfflineThreshold - time.Second), CreatedAt: enrolled},
		// Swept, and never in contact at all: both count as not in contact.
		{ID: "n4", Online: false, LastSeen: now.Add(-6 * time.Hour), CreatedAt: enrolled},
		{ID: "n5", CreatedAt: enrolled},
	}
	byStatus := srv.nodeStatusIndex(nodes, now)
	if got := byStatus["n2"].Status; got != NodeStatusDisabled {
		t.Fatalf("n2 derived %q, want %q", got, NodeStatusDisabled)
	}
	if got := byStatus["n3"].Status; got != NodeStatusOffline {
		t.Fatalf("n3 derived %q, want %q", got, NodeStatusOffline)
	}

	r, resolved := rollupFor([]string{"n1", "n2", "n3", "n4", "n5", "ghost"}, byStatus)
	if r.Total != 5 || r.Online != 1 || r.Offline != 3 || r.Disabled != 1 {
		t.Fatalf("unexpected rollup: %+v", r)
	}
	if r.Online+r.Offline+r.Disabled != r.Total {
		t.Fatalf("the buckets do not add up to total: %+v", r)
	}
	if len(resolved) != 5 {
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
