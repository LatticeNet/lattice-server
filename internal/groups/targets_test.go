package groups

import (
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestResolveTargets(t *testing.T) {
	nodes := fixtureNodes()
	groupList := []model.Group{
		{ID: "g-prod", Selector: sel(model.GroupSelector{MatchTagsAny: []string{"prod"}})},
		{ID: "g-pinned", Members: []string{"node_c", "node_gone"}},
	}

	tests := []struct {
		name string
		sel  model.TargetSelector
		want []string
	}{
		{name: "empty selector targets nothing", sel: model.TargetSelector{}, want: []string{}},
		{name: "explicit nodes, sorted and deduped", sel: model.TargetSelector{Nodes: []string{"node_c", "node_a", "node_c"}}, want: []string{"node_a", "node_c"}},
		{name: "an explicit node not in the fleet is dropped", sel: model.TargetSelector{Nodes: []string{"node_gone", "node_b"}}, want: []string{"node_b"}},
		{name: "explicit ids are trimmed", sel: model.TargetSelector{Nodes: []string{" node_a "}}, want: []string{"node_a"}},
		{name: "a group contributes its resolved members", sel: model.TargetSelector{Groups: []string{"g-prod"}}, want: []string{"node_a", "node_b"}},
		{name: "a stale pinned member of a group is dropped", sel: model.TargetSelector{Groups: []string{"g-pinned"}}, want: []string{"node_c"}},
		{name: "an unknown group contributes nothing", sel: model.TargetSelector{Groups: []string{"g-missing"}}, want: []string{}},
		{name: "nodes and groups union", sel: model.TargetSelector{Nodes: []string{"node_d"}, Groups: []string{"g-prod", "g-pinned"}}, want: []string{"node_a", "node_b", "node_c", "node_d"}},
		{name: "all is the whole fleet", sel: model.TargetSelector{All: true}, want: []string{"node_a", "node_b", "node_c", "node_d"}},
		{name: "exclude subtracts from all", sel: model.TargetSelector{All: true, Exclude: []string{"node_b", "node_gone"}}, want: []string{"node_a", "node_c", "node_d"}},
		{name: "exclude subtracts from a group", sel: model.TargetSelector{Groups: []string{"g-prod"}, Exclude: []string{"node_a"}}, want: []string{"node_b"}},
		{name: "exclude wins over an explicit node", sel: model.TargetSelector{Nodes: []string{"node_a"}, Exclude: []string{"node_a"}}, want: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveTargets(tc.sel, nodes, groupList)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ResolveTargets(%+v) = %v, want %v", tc.sel, got, tc.want)
			}
		})
	}
}
