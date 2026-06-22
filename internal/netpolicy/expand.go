package netpolicy

import (
	"sort"

	"github.com/LatticeNet/lattice-sdk/model"
)

// ExpandGroupPolicies materializes group-scoped policies into one per-node
// model.NetPolicy per node covered by any policy's scope group. A rule whose
// remote is a group (NetRefGroup) fans out to one node-ref rule per resolved
// remote member, so the UNCHANGED per-node compiler never sees a group ref.
//
// Policies apply in (Priority, ID) order; within a policy, rule order is
// preserved. resolved maps a group ID to its resolved member node IDs (as
// produced by internal/groups.ResolveAll).
//
// The returned policies are tagged GroupDerived=true and keyed by target node
// ID. Because they contain CONCRETE node refs, the compiled plan SHA changes
// whenever membership changes — closing the plan-staleness gap by construction
// (a node joining/leaving a remote group changes the rule set, hence the SHA).
func ExpandGroupPolicies(policies []model.GroupNetPolicy, resolved map[string][]string) map[string]model.NetPolicy {
	sorted := append([]model.GroupNetPolicy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})

	out := map[string]model.NetPolicy{}
	for _, gp := range sorted {
		if !gp.Enabled {
			continue
		}
		for _, target := range resolved[gp.ScopeGroupID] {
			rules := expandRulesForTarget(gp.Rules, target, resolved)
			if len(rules) == 0 {
				continue
			}
			np, ok := out[target]
			if !ok {
				np = model.NetPolicy{
					ID:           target,
					TargetNodeID: target,
					Enabled:      true,
					GroupDerived: true,
				}
			}
			np.Rules = append(np.Rules, rules...)
			out[target] = np
		}
	}
	return out
}

// expandRulesForTarget turns one group policy's rules into concrete per-node
// rules for a single target node. Group remotes fan out to resolved members
// (skipping the target itself); other remote kinds pass through unchanged.
// Disabled rules are dropped.
func expandRulesForTarget(rules []model.GroupNetRule, target string, resolved map[string][]string) []model.NetRule {
	out := make([]model.NetRule, 0, len(rules))
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		if r.Remote.Kind == model.NetRefGroup {
			for _, member := range resolved[r.Remote.GroupID] {
				if member == target {
					continue // a node never needs a rule targeting itself
				}
				out = append(out, model.NetRule{
					ID:        r.ID + ":" + member,
					Comment:   r.Comment,
					Action:    r.Action,
					Direction: r.Direction,
					Protocol:  r.Protocol,
					Ports:     append([]int(nil), r.Ports...),
					Remote:    model.NetEndpoint{Kind: model.NetRefNode, NodeID: member},
				})
			}
			continue
		}
		out = append(out, model.NetRule{
			ID:        r.ID,
			Comment:   r.Comment,
			Action:    r.Action,
			Direction: r.Direction,
			Protocol:  r.Protocol,
			Ports:     append([]int(nil), r.Ports...),
			Remote:    r.Remote,
		})
	}
	return out
}
