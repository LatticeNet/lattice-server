package groups

import (
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// ResolveTargets resolves a target selector (design 32 D5) against the fleet.
// The result is the union of the named nodes, the resolved members of each
// named group (ResolveMembers; an unknown group contributes nothing) and every
// node when All is set, minus the nodes in Exclude. Only ids present in nodes
// survive, so a stale explicit node or pinned group member is dropped. Ids are
// trimmed; the result is deduplicated and sorted, and never nil.
func ResolveTargets(sel model.TargetSelector, nodes []model.Node, groups []model.Group) []string {
	fleet := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		fleet[n.ID] = struct{}{}
	}
	set := make(map[string]struct{})
	add := func(id string) {
		id = strings.TrimSpace(id)
		if _, ok := fleet[id]; ok {
			set[id] = struct{}{}
		}
	}
	if sel.All {
		for id := range fleet {
			set[id] = struct{}{}
		}
	}
	for _, id := range sel.Nodes {
		add(id)
	}
	if len(sel.Groups) > 0 {
		byID := make(map[string]model.Group, len(groups))
		for _, g := range groups {
			byID[g.ID] = g
		}
		for _, gid := range sel.Groups {
			g, ok := byID[strings.TrimSpace(gid)]
			if !ok {
				continue
			}
			for _, id := range ResolveMembers(g, nodes) {
				add(id)
			}
		}
	}
	for _, id := range sel.Exclude {
		delete(set, strings.TrimSpace(id))
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
