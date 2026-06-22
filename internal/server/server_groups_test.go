package server

import (
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
