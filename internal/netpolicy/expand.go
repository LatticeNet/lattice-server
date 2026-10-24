package netpolicy

import (
	"fmt"
	"sort"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
)

// PolicyTargets resolves every policy's target selector (its TargetScope:
// the stored scope, or the one-group selector scope_group_id stands for)
// against the fleet, keyed by policy ID. Disabled policies are resolved too,
// because callers that ask what a policy reaches ask regardless of state.
func PolicyTargets(policies []model.GroupNetPolicy, nodes []model.Node, groupList []model.Group) map[string][]string {
	out := make(map[string][]string, len(policies))
	for _, gp := range policies {
		out[gp.ID] = groups.ResolveTargets(gp.TargetScope(), nodes, groupList)
	}
	return out
}

// ExpandGroupPolicies materializes outbound policies into one per-node
// model.NetPolicy per node any enabled policy targets. targets maps a policy
// ID to its resolved target nodes (PolicyTargets), so one node, several nodes,
// groups and the whole fleet all expand the same way. A rule whose remote is a
// group (NetRefGroup) fans out to one node-ref rule per resolved remote member,
// so the UNCHANGED per-node compiler never sees a group ref.
//
// Policies apply in (Priority, ID) order; within a policy, rule order is
// preserved. resolved maps a group ID to its resolved member node IDs (as
// produced by internal/groups.ResolveAll).
//
// The returned policies are tagged GroupDerived=true and keyed by target node
// ID. Because they contain CONCRETE node refs, the compiled plan SHA changes
// whenever membership changes — closing the plan-staleness gap by construction
// (a node joining/leaving a remote group changes the rule set, hence the SHA).
func ExpandGroupPolicies(policies []model.GroupNetPolicy, targets map[string][]string, resolved map[string][]string) map[string]model.NetPolicy {
	sorted := append([]model.GroupNetPolicy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})

	out := map[string]model.NetPolicy{}
	usedIDs := map[string]map[string]struct{}{}
	for _, gp := range sorted {
		if !gp.Enabled {
			continue
		}
		for _, target := range targets[gp.ID] {
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
			used := usedIDs[target]
			if used == nil {
				used = map[string]struct{}{}
				usedIDs[target] = used
			}
			for i := range rules {
				rules[i].ID = uniqueRuleID(rules[i].ID, gp.ID, used)
			}
			np.Rules = append(np.Rules, rules...)
			out[target] = np
		}
	}
	return out
}

// uniqueRuleID keeps a merged node policy free of duplicate rule ids, which
// NormalizePolicy refuses. Policies authored apart reuse ids ("rule_001"), and
// with selector targets several of them reach one node routinely. A rule
// keeps its id unless an earlier policy on the node already used it; then it
// takes its policy's id as a prefix. A node without a collision therefore
// compiles exactly the ruleset it did before, since rule ids appear in the
// nft comments.
func uniqueRuleID(ruleID, policyID string, used map[string]struct{}) string {
	candidate := ruleID
	if _, taken := used[candidate]; taken {
		candidate = policyID + ":" + ruleID
		for n := 2; ; n++ {
			if _, taken := used[candidate]; !taken {
				break
			}
			candidate = fmt.Sprintf("%s:%s:%d", policyID, ruleID, n)
		}
	}
	used[candidate] = struct{}{}
	return candidate
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
