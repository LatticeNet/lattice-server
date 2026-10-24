package groups

import (
	"sort"

	"github.com/LatticeNet/lattice-sdk/model"
)

// ResolveTargets resolves a target selector (design 32 D5) against the fleet
// as it is now: the ids of the nodes it selects, sorted and without repeats.
// A node is selected when sel.All is set, when sel.Nodes names it, or when it
// is a member of a group sel.Groups names, resolved by ResolveMembers, so a
// group's selector criteria combine with AND exactly as everywhere else. A
// node sel.Exclude names is never selected.
//
// Only nodes in nodes are returned: an explicit id or a group member with no
// node record selects nothing, and a group id that names no group
// contributes nothing. Disabled nodes are returned like any other; whether a
// disabled node takes part is the caller's decision.
func ResolveTargets(sel model.TargetSelector, nodes []model.Node, groups []model.Group) []string {
	exists := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		exists[n.ID] = true
	}
	picked := map[string]bool{}
	if sel.All {
		for id := range exists {
			picked[id] = true
		}
	}
	for _, id := range sel.Nodes {
		if exists[id] {
			picked[id] = true
		}
	}
	if len(sel.Groups) > 0 {
		named := make(map[string]bool, len(sel.Groups))
		for _, id := range sel.Groups {
			named[id] = true
		}
		for _, g := range groups {
			if !named[g.ID] {
				continue
			}
			for _, id := range ResolveMembers(g, nodes) {
				if exists[id] {
					picked[id] = true
				}
			}
		}
	}
	for _, id := range sel.Exclude {
		delete(picked, id)
	}
	out := make([]string, 0, len(picked))
	for id := range picked {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
