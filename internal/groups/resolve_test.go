package groups

import (
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// fixtureNodes is a small but realistic fleet used across the table tests:
//
//	node_a — role web, tags [edge prod], US (North America)
//	node_b — role db,  tags [prod],      DE (Europe)
//	node_c — role web, tags [canary],    JP (Asia)
//	node_d — no role,  no tags,          no geo
func fixtureNodes() []model.Node {
	return []model.Node{
		{ID: "node_a", Role: "web", Tags: []string{"edge", "prod"}, Geo: &model.NodeGeo{Country: "US"}},
		{ID: "node_b", Role: "db", Tags: []string{"prod"}, Geo: &model.NodeGeo{Country: "DE"}},
		{ID: "node_c", Role: "web", Tags: []string{"canary"}, Geo: &model.NodeGeo{Country: "JP"}},
		{ID: "node_d"},
	}
}

func sel(s model.GroupSelector) *model.GroupSelector { return &s }

func TestResolveMembers(t *testing.T) {
	nodes := fixtureNodes()

	tests := []struct {
		name  string
		group model.Group
		want  []string
	}{
		{
			name:  "static only dedups and sorts",
			group: model.Group{Members: []string{"node_b", "node_a", "node_a"}},
			want:  []string{"node_a", "node_b"},
		},
		{
			name:  "static membership is verbatim even for unknown nodes",
			group: model.Group{Members: []string{"node_zz", "node_a"}},
			want:  []string{"node_a", "node_zz"},
		},
		{
			name:  "selector tags-any",
			group: model.Group{Selector: sel(model.GroupSelector{MatchTagsAny: []string{"prod"}})},
			want:  []string{"node_a", "node_b"},
		},
		{
			name:  "selector tags-any multiple values is an OR-set",
			group: model.Group{Selector: sel(model.GroupSelector{MatchTagsAny: []string{"canary", "edge"}})},
			want:  []string{"node_a", "node_c"},
		},
		{
			name:  "selector roles",
			group: model.Group{Selector: sel(model.GroupSelector{MatchRoles: []string{"web"}})},
			want:  []string{"node_a", "node_c"},
		},
		{
			name:  "selector country",
			group: model.Group{Selector: sel(model.GroupSelector{MatchCountry: []string{"US", "JP"}})},
			want:  []string{"node_a", "node_c"},
		},
		{
			name:  "selector country is case-insensitive",
			group: model.Group{Selector: sel(model.GroupSelector{MatchCountry: []string{"us"}})},
			want:  []string{"node_a"},
		},
		{
			name:  "selector continent",
			group: model.Group{Selector: sel(model.GroupSelector{MatchContinent: []string{"EU"}})},
			want:  []string{"node_b"},
		},
		{
			name:  "selector continent asia",
			group: model.Group{Selector: sel(model.GroupSelector{MatchContinent: []string{"AS"}})},
			want:  []string{"node_c"},
		},
		{
			name: "union of explicit members and selector with dedup",
			group: model.Group{
				Members:  []string{"node_a"},
				Selector: sel(model.GroupSelector{MatchRoles: []string{"web"}}),
			},
			want: []string{"node_a", "node_c"},
		},
		{
			name: "multi-criteria selector is AND-ed (web AND in Asia)",
			group: model.Group{Selector: sel(model.GroupSelector{
				MatchRoles:     []string{"web"},
				MatchContinent: []string{"AS"},
			})},
			want: []string{"node_c"},
		},
		{
			name:  "empty group resolves to nothing",
			group: model.Group{},
			want:  nil,
		},
		{
			name:  "empty selector matches nobody (never widen to whole fleet)",
			group: model.Group{Selector: sel(model.GroupSelector{})},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveMembers(tt.group, nodes)
			if !equalStrings(got, tt.want) {
				t.Fatalf("ResolveMembers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveAllAndGroupIDsForNode(t *testing.T) {
	nodes := fixtureNodes()
	groups := []model.Group{
		{ID: "grp_static", Members: []string{"node_a"}},
		{ID: "grp_web", Selector: sel(model.GroupSelector{MatchRoles: []string{"web"}})},
		{ID: "grp_eu", Selector: sel(model.GroupSelector{MatchContinent: []string{"EU"}})},
	}

	resolved := ResolveAll(groups, nodes)

	wantResolved := map[string][]string{
		"grp_static": {"node_a"},
		"grp_web":    {"node_a", "node_c"},
		"grp_eu":     {"node_b"},
	}
	if !reflect.DeepEqual(resolved, wantResolved) {
		t.Fatalf("ResolveAll() = %v, want %v", resolved, wantResolved)
	}

	// Reverse lookup round-trip.
	cases := map[string][]string{
		"node_a": {"grp_static", "grp_web"}, // explicit + selector
		"node_b": {"grp_eu"},
		"node_c": {"grp_web"},
		"node_d": nil, // in no group
	}
	for nodeID, want := range cases {
		got := GroupIDsForNode(nodeID, resolved)
		if !equalStrings(got, want) {
			t.Fatalf("GroupIDsForNode(%q) = %v, want %v", nodeID, got, want)
		}
	}
}

func TestContinentOf(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"US", "NA"},
		{"us", "NA"}, // case-insensitive
		{"DE", "EU"},
		{"JP", "AS"},
		{"BR", "SA"},
		{"ZA", "AF"},
		{"AU", "OC"},
		{"AQ", "AN"},
		{"NA", "AF"},  // Namibia, per the fleet.ts quirk
		{"AS", "OC"},  // American Samoa, per the fleet.ts quirk
		{"", "??"},    // empty
		{"ZZ", "??"},  // unknown
		{"USA", "??"}, // not two letters
	}
	for _, tt := range tests {
		if got := continentOf(tt.code); got != tt.want {
			t.Errorf("continentOf(%q) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

// equalStrings treats a nil slice and a zero-length slice as equal so callers
// don't have to care whether "no members" is returned as nil or []string{}.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
