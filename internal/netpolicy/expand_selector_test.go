package netpolicy

import (
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
)

func selectorFleet() ([]model.Node, []model.Group) {
	nodes := []model.Node{{ID: "n1"}, {ID: "n2"}, {ID: "n3"}, {ID: "n4"}}
	groupList := []model.Group{
		{ID: "g-web", Members: []string{"n1", "n2"}},
		{ID: "g-db", Members: []string{"n3", "n4"}},
	}
	return nodes, groupList
}

func ruleIDs(np model.NetPolicy) []string {
	out := make([]string, 0, len(np.Rules))
	for _, r := range np.Rules {
		out = append(out, r.ID)
	}
	return out
}

// Single-node, several-node and group targets are one GroupNetPolicy each, and
// each expands onto exactly the nodes its selector resolves to.
func TestExpandSelectorScopedPolicies(t *testing.T) {
	nodes, groupList := selectorFleet()
	allow := func(id string) []model.GroupNetRule {
		return []model.GroupNetRule{{ID: id, Action: "allow", Direction: "egress", Protocol: "tcp", Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}}
	}
	policies := []model.GroupNetPolicy{
		{ID: "gnp_three", Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n1", "n3", "n4"}}, Rules: allow("three")},
		{ID: "gnp_group", Enabled: true, Scope: &model.TargetSelector{Groups: []string{"g-db"}, Exclude: []string{"n4"}}, Rules: allow("group")},
		{ID: "gnp_fleet", Enabled: true, Priority: 50, Scope: &model.TargetSelector{All: true, Exclude: []string{"n1"}}, Rules: allow("fleet")},
	}
	resolved := groups.ResolveAll(groupList, nodes)
	targets := PolicyTargets(policies, nodes, groupList)
	if got := targets["gnp_three"]; !reflect.DeepEqual(got, []string{"n1", "n3", "n4"}) {
		t.Fatalf("three-node policy targets %v", got)
	}
	out := ExpandGroupPolicies(policies, targets, resolved)
	want := map[string][]string{
		"n1": {"three"},
		"n2": {"fleet"},
		"n3": {"group", "three", "fleet"},
		"n4": {"three", "fleet"},
	}
	if len(out) != len(want) {
		t.Fatalf("expanded onto %d nodes, want %d: %+v", len(out), len(want), out)
	}
	for node, ids := range want {
		np, ok := out[node]
		if !ok {
			t.Fatalf("no policy for %s", node)
		}
		if !np.GroupDerived || np.TargetNodeID != node || np.ID != node {
			t.Fatalf("bad header for %s: %+v", node, np)
		}
		if got := ruleIDs(np); !reflect.DeepEqual(got, ids) {
			t.Fatalf("%s rules %v, want %v (priority, then id order)", node, got, ids)
		}
	}
}

// A policy stored before selectors names only scope_group_id. It must expand
// exactly as it did: onto the members of that group.
func TestExpandScopeGroupIDAliasUnchanged(t *testing.T) {
	nodes, groupList := selectorFleet()
	policies := []model.GroupNetPolicy{{
		ID: "gnp_old", ScopeGroupID: "g-web", Enabled: true,
		Rules: []model.GroupNetRule{{ID: "r", Action: "allow", Direction: "egress", Protocol: "tcp", Ports: []int{5432},
			Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "g-db"}}},
	}}
	resolved := groups.ResolveAll(groupList, nodes)
	out := ExpandGroupPolicies(policies, PolicyTargets(policies, nodes, groupList), resolved)
	if len(out) != 2 {
		t.Fatalf("expected the two g-web members, got %+v", out)
	}
	for _, node := range []string{"n1", "n2"} {
		if got := ruleIDs(out[node]); !reflect.DeepEqual(got, []string{"r:n3", "r:n4"}) {
			t.Fatalf("%s rules %v, want the g-db fan-out", node, got)
		}
	}
}

// A remote group is expanded to its members for every target kind, not only
// for group-scoped policies.
func TestExpandRemoteGroupOnNodeTarget(t *testing.T) {
	nodes, groupList := selectorFleet()
	policies := []model.GroupNetPolicy{{
		ID: "gnp_one", Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n3"}},
		Rules: []model.GroupNetRule{{ID: "r", Action: "allow", Direction: "egress", Protocol: "tcp", Ports: []int{22},
			Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "g-db"}}},
	}}
	out := ExpandGroupPolicies(policies, PolicyTargets(policies, nodes, groupList), groups.ResolveAll(groupList, nodes))
	np := out["n3"]
	if got := ruleIDs(np); !reflect.DeepEqual(got, []string{"r:n4"}) {
		t.Fatalf("n3 rules %v, want the remote group fanned to n4 and itself skipped", got)
	}
	if np.Rules[0].Remote != (model.NetEndpoint{Kind: model.NetRefNode, NodeID: "n4"}) {
		t.Fatalf("remote not expanded to a node ref: %+v", np.Rules[0].Remote)
	}
}

// Two policies written by the same form both carry "rule_001". Before
// selectors that collision needed one node in two scope groups; with
// overlapping targets it is the common case, and NormalizePolicy refuses a
// node policy with a duplicate rule id, so the node got no plan at all. The
// later policy's colliding rule is renamed with its policy id, and a node
// with no collision keeps the ids, and so the ruleset, it had.
func TestExpandKeepsRuleIDsUniqueAcrossPolicies(t *testing.T) {
	nodes, groupList := selectorFleet()
	rule := func(id string, port int) model.GroupNetRule {
		return model.GroupNetRule{ID: id, Action: "allow", Direction: "egress", Protocol: "tcp", Ports: []int{port}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}
	}
	policies := []model.GroupNetPolicy{
		{ID: "gnp_a", Enabled: true, Scope: &model.TargetSelector{All: true}, Rules: []model.GroupNetRule{rule("rule_001", 443)}},
		{ID: "gnp_b", Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n1"}}, Rules: []model.GroupNetRule{rule("rule_001", 22), rule("rule_002", 80)}},
	}
	out := ExpandGroupPolicies(policies, PolicyTargets(policies, nodes, groupList), groups.ResolveAll(groupList, nodes))
	if got := ruleIDs(out["n1"]); !reflect.DeepEqual(got, []string{"rule_001", "gnp_b:rule_001", "rule_002"}) {
		t.Fatalf("n1 rules %v, want the later collision renamed", got)
	}
	if got := ruleIDs(out["n2"]); !reflect.DeepEqual(got, []string{"rule_001"}) {
		t.Fatalf("n2 rules %v, want its ids unchanged", got)
	}
}
