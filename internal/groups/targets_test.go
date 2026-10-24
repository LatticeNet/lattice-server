package groups

import (
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestResolveTargets(t *testing.T) {
	nodes := []model.Node{
		{ID: "n-jp", Tags: []string{"edge"}, Geo: &model.NodeGeo{Country: "JP"}},
		{ID: "n-hk", Tags: []string{"edge"}, Geo: &model.NodeGeo{Country: "HK"}},
		{ID: "n-de", Geo: &model.NodeGeo{Country: "DE"}},
		{ID: "n-us", Tags: []string{"core"}, Geo: &model.NodeGeo{Country: "US"}},
	}
	groups := []model.Group{
		// Explicit members, one of them a node that no longer exists.
		{ID: "grp_pinned", Members: []string{"n-de", "n-gone"}},
		// A selector whose two criteria combine with AND: edge-tagged
		// nodes in Asia, which n-us (core) and n-de (Europe) are not.
		{ID: "grp_asia_edge", Selector: &model.GroupSelector{MatchTagsAny: []string{"edge"}, MatchContinent: []string{"AS"}}},
	}
	cases := []struct {
		name string
		sel  model.TargetSelector
		want []string
	}{
		{"empty selects nothing", model.TargetSelector{}, []string{}},
		{"explicit nodes, unknown dropped, repeats folded", model.TargetSelector{Nodes: []string{"n-us", "n-gone", "n-us"}}, []string{"n-us"}},
		{"group members are existing nodes only", model.TargetSelector{Groups: []string{"grp_pinned"}}, []string{"n-de"}},
		{"group selector through the resolver", model.TargetSelector{Groups: []string{"grp_asia_edge"}}, []string{"n-hk", "n-jp"}},
		{"unknown group contributes nothing", model.TargetSelector{Groups: []string{"grp_none"}, Nodes: []string{"n-de"}}, []string{"n-de"}},
		{"whole fleet", model.TargetSelector{All: true}, []string{"n-de", "n-hk", "n-jp", "n-us"}},
		{"exclusion wins over every criterion", model.TargetSelector{All: true, Nodes: []string{"n-jp"}, Groups: []string{"grp_asia_edge"}, Exclude: []string{"n-jp", "n-de"}}, []string{"n-hk", "n-us"}},
		{"union of nodes and groups, sorted", model.TargetSelector{Nodes: []string{"n-us"}, Groups: []string{"grp_pinned", "grp_asia_edge"}}, []string{"n-de", "n-hk", "n-jp", "n-us"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveTargets(tc.sel, nodes, groups)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ResolveTargets(%+v) = %v, want %v", tc.sel, got, tc.want)
			}
		})
	}
}
