package store

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
)

// Security groups bound to node groups (design 32 D3, S4). A binding never
// adopts a node: a member NetGuard does not manage lists the binding as
// inactive and compiles nothing from it. On a managed member the bound
// groups follow the node's own groups, by node group name, each node group's
// list in its order, and a group already in force earlier is not repeated.
// Nothing reaches a node without a NetGuard plan the operator approves; the
// writes here only clear the plan anchors they make stale.

// ErrGuardReferenceMissing is returned when a node-group binding names a
// node group or a security group that does not exist.
var ErrGuardReferenceMissing = errors.New("guard binding names a missing record")

// DerivedGuardGroup is one security group a node receives through a node
// group's binding, with the node group's name for the sentences that
// describe it.
type DerivedGuardGroup struct {
	model.DerivedSecurityGroup
	NodeGroupName string
}

func cloneNodeGroupGuardBinding(b model.NodeGroupGuardBinding) model.NodeGroupGuardBinding {
	b.SecurityGroupIDs = append([]string(nil), b.SecurityGroupIDs...)
	return b
}

// UpsertNodeGroupGuardBinding creates or updates a node group's binding with
// the optimistic-concurrency contract of UpsertSecurityGroup. The node group
// and every security group must exist, checked under the same lock as the
// write so a concurrent delete cannot leave a dangling reference. Every
// member's plan anchor is cleared: its compile changes.
func (s *Store) UpsertNodeGroupGuardBinding(b model.NodeGroupGuardBinding) (model.NodeGroupGuardBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Groups[b.GroupID]; !ok {
		return model.NodeGroupGuardBinding{}, fmt.Errorf("%w: node group %q not found", ErrGuardReferenceMissing, b.GroupID)
	}
	for _, id := range b.SecurityGroupIDs {
		if _, ok := s.state.SecurityGroups[id]; !ok {
			return model.NodeGroupGuardBinding{}, fmt.Errorf("%w: security group %q not found", ErrGuardReferenceMissing, id)
		}
	}
	now := time.Now().UTC()
	if existing, ok := s.state.NodeGroupGuardBindings[b.GroupID]; ok {
		if b.Version != existing.Version {
			return model.NodeGroupGuardBinding{}, ErrGuardVersionConflict
		}
		b.CreatedAt = existing.CreatedAt
	} else {
		if b.Version != 0 {
			return model.NodeGroupGuardBinding{}, ErrGuardVersionConflict
		}
		b.CreatedAt = now
	}
	b.Version++
	b.UpdatedAt = now
	if b.SecurityGroupIDs == nil {
		b.SecurityGroupIDs = []string{}
	}
	s.state.NodeGroupGuardBindings[b.GroupID] = cloneNodeGroupGuardBinding(b)
	s.invalidateGuardBindingsForNodeGroupLocked(b.GroupID, true)
	if err := s.Save(); err != nil {
		return model.NodeGroupGuardBinding{}, err
	}
	return cloneNodeGroupGuardBinding(b), nil
}

// NodeGroupGuardBinding returns a node group's binding.
func (s *Store) NodeGroupGuardBinding(groupID string) (model.NodeGroupGuardBinding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.state.NodeGroupGuardBindings[groupID]
	return cloneNodeGroupGuardBinding(b), ok
}

// NodeGroupGuardBindings returns every node-group binding sorted by node
// group id.
func (s *Store) NodeGroupGuardBindings() []model.NodeGroupGuardBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.NodeGroupGuardBinding, 0, len(s.state.NodeGroupGuardBindings))
	for _, b := range s.state.NodeGroupGuardBindings {
		out = append(out, cloneNodeGroupGuardBinding(b))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GroupID < out[j].GroupID })
	return out
}

// DeleteNodeGroupGuardBinding removes a node group's binding and reports
// whether there was one. Like a binding edit it changes nothing on any node;
// the members' plan anchors are cleared so their next plan drops the groups.
func (s *Store) DeleteNodeGroupGuardBinding(groupID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.NodeGroupGuardBindings[groupID]; !ok {
		return false, nil
	}
	s.invalidateGuardBindingsForNodeGroupLocked(groupID, true)
	delete(s.state.NodeGroupGuardBindings, groupID)
	return true, s.Save()
}

// NodeGroupsBindingSecurityGroup lists, sorted, the node groups whose binding
// names the security group.
func (s *Store) NodeGroupsBindingSecurityGroup(securityGroupID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for groupID, b := range s.state.NodeGroupGuardBindings {
		for _, id := range b.SecurityGroupIDs {
			if id == securityGroupID {
				out = append(out, groupID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// derivedGuardGroupsLocked lists, in compile order, the security groups node
// receives through node-group bindings. own is the node's own group list; a
// derived group that repeats one of them, or an earlier derived one, is left
// out, since compiling the same rules twice changes nothing but the review.
func (s *Store) derivedGuardGroupsLocked(node model.Node, own []string) []DerivedGuardGroup {
	type bound struct {
		group   model.Group
		binding model.NodeGroupGuardBinding
	}
	var through []bound
	for groupID, b := range s.state.NodeGroupGuardBindings {
		if len(b.SecurityGroupIDs) == 0 {
			continue
		}
		g, ok := s.state.Groups[groupID]
		if !ok || !groups.Contains(g, node) {
			continue
		}
		through = append(through, bound{group: g, binding: b})
	}
	sort.Slice(through, func(i, j int) bool {
		if through[i].group.Name != through[j].group.Name {
			return through[i].group.Name < through[j].group.Name
		}
		return through[i].group.ID < through[j].group.ID
	})
	seen := make(map[string]bool, len(own))
	for _, id := range own {
		seen[id] = true
	}
	out := []DerivedGuardGroup{}
	for _, b := range through {
		for _, id := range b.binding.SecurityGroupIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, DerivedGuardGroup{
				DerivedSecurityGroup: model.DerivedSecurityGroup{SecurityGroupID: id, NodeGroupID: b.group.ID},
				NodeGroupName:        b.group.Name,
			})
		}
	}
	return out
}

// NodeDerivedGuardGroups lists, in compile order, the security groups a node
// receives through node-group bindings, whether or not NetGuard manages it.
func (s *Store) NodeDerivedGuardGroups(nodeID string) []DerivedGuardGroup {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.state.Nodes[nodeID]
	if !ok {
		return []DerivedGuardGroup{}
	}
	return s.derivedGuardGroupsLocked(node, s.state.GuardBindings[nodeID].GroupIDs)
}

// NetGuardRuleRemoteNodes lists, sorted, the nodes other than nodeID whose
// addresses a NetGuard compile of nodeID renders: node remotes in its rules,
// and the members of node group remotes. It reads the binding and the
// groups without copying the fleet, for the approvals list's reach check.
func (s *Store) NetGuardRuleRemoteNodes(nodeID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.state.GuardBindings[nodeID]
	if !ok {
		return nil
	}
	set := map[string]bool{}
	resolved := map[string]bool{}
	for _, rule := range s.bindingRulesLocked(nodeID, binding) {
		switch rule.Remote.Kind {
		case model.NetRefNode:
			set[rule.Remote.NodeID] = true
		case model.NetRefGroup:
			g, ok := s.state.Groups[rule.Remote.GroupID]
			if !ok || resolved[g.ID] {
				continue
			}
			resolved[g.ID] = true
			for _, member := range g.Members {
				set[member] = true
			}
			if g.Selector != nil {
				for _, n := range s.state.Nodes {
					if groups.Contains(g, n) {
						set[n.ID] = true
					}
				}
			}
		}
	}
	delete(set, nodeID)
	delete(set, "")
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// derivedOf strips the names a snapshot carries for display.
func derivedOf(derived []DerivedGuardGroup) []model.DerivedSecurityGroup {
	out := make([]model.DerivedSecurityGroup, 0, len(derived))
	for _, d := range derived {
		out = append(out, d.DerivedSecurityGroup)
	}
	return out
}

// remoteGroupMembersLocked resolves every node group a rule names as its
// remote, against the whole fleet.
func (s *Store) remoteGroupMembersLocked(overrides []model.GuardRule, compiled []model.SecurityGroup) map[string][]string {
	out := map[string][]string{}
	var nodes []model.Node
	add := func(rules []model.GuardRule) {
		for _, rule := range rules {
			if rule.Remote.Kind != model.NetRefGroup {
				continue
			}
			if _, done := out[rule.Remote.GroupID]; done {
				continue
			}
			g, ok := s.state.Groups[rule.Remote.GroupID]
			if !ok {
				continue
			}
			if nodes == nil {
				nodes = make([]model.Node, 0, len(s.state.Nodes))
				for _, n := range s.state.Nodes {
					nodes = append(nodes, n)
				}
			}
			out[g.ID] = groups.ResolveMembers(g, nodes)
		}
	}
	add(overrides)
	for _, group := range compiled {
		add(group.Rules)
	}
	return out
}

// NetGuardCoverage says whether NetGuard owns lattice_guard on a node or is
// meant to (design 32 D7 with S4): managed is a managed binding of its own;
// viaGroup names the first node group, by name, whose binding names a
// security group and that the node belongs to. Either one makes the legacy
// writers refuse the node.
func (s *Store) NetGuardCoverage(nodeID string) (managed bool, viaGroup string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.netGuardCoverageLocked(s.state, nodeID)
}

func (s *Store) netGuardCoverageLocked(st State, nodeID string) (managed bool, viaGroup string) {
	if binding, ok := st.GuardBindings[nodeID]; ok && binding.Managed {
		managed = true
	}
	node, ok := st.Nodes[nodeID]
	if !ok {
		return managed, ""
	}
	for groupID, b := range st.NodeGroupGuardBindings {
		if len(b.SecurityGroupIDs) == 0 {
			continue
		}
		g, ok := st.Groups[groupID]
		if !ok || !groups.Contains(g, node) {
			continue
		}
		if viaGroup == "" || g.Name < viaGroup {
			viaGroup = g.Name
		}
	}
	return managed, viaGroup
}

// bindingRulesLocked is every rule a binding's compile reads: its overrides,
// its own groups', and the derived groups' when it is managed.
func (s *Store) bindingRulesLocked(nodeID string, binding model.NodeGuardBinding) []model.GuardRule {
	rules := append([]model.GuardRule(nil), binding.Overrides...)
	for _, groupID := range binding.GroupIDs {
		rules = append(rules, s.state.SecurityGroups[groupID].Rules...)
	}
	if binding.Managed {
		if node, ok := s.state.Nodes[nodeID]; ok {
			for _, derived := range s.derivedGuardGroupsLocked(node, binding.GroupIDs) {
				rules = append(rules, s.state.SecurityGroups[derived.SecurityGroupID].Rules...)
			}
		}
	}
	return rules
}

// invalidateGuardBindingsForNodeGroupLocked clears the plan anchor of every
// node whose rules name the group as a remote and, with members, of every
// managed member, whose derived groups change with the group's binding or
// its membership.
func (s *Store) invalidateGuardBindingsForNodeGroupLocked(groupID string, members bool) {
	g, exists := s.state.Groups[groupID]
	for nodeID, binding := range s.state.GuardBindings {
		if binding.LastPlanSHA == "" {
			continue
		}
		if exists && members {
			if node, ok := s.state.Nodes[nodeID]; ok && binding.Managed && groups.Contains(g, node) {
				s.invalidateGuardBindingLocked(nodeID)
				continue
			}
		}
		if guardRulesReferenceGroup(s.bindingRulesLocked(nodeID, binding), groupID) {
			s.invalidateGuardBindingLocked(nodeID)
		}
	}
}

// invalidateGuardBindingsForMembershipLocked runs when a node's fields that
// selectors read (tags, role, geo) may have changed. For each node group
// whose membership of the node moves, the node's derived groups change when
// the group binds any, and every compile naming the group as a remote
// renders different addresses; both anchors are cleared so the approved
// plan made for the old membership is withheld at lease.
func (s *Store) invalidateGuardBindingsForMembershipLocked(previous, next model.Node) {
	if len(s.state.GuardBindings) == 0 {
		return
	}
	for groupID, g := range s.state.Groups {
		if g.Selector == nil || groups.Contains(g, previous) == groups.Contains(g, next) {
			continue
		}
		if b, ok := s.state.NodeGroupGuardBindings[groupID]; ok && len(b.SecurityGroupIDs) > 0 {
			s.invalidateGuardBindingLocked(next.ID)
		}
		s.invalidateGuardBindingsForNodeGroupLocked(groupID, false)
	}
}

// invalidateGuardBindingsForGroupEditLocked runs around a node group's edit
// or delete: its membership may change, which moves the derived groups of a
// bound group's members and the addresses of a group remote.
func (s *Store) invalidateGuardBindingsForGroupEditLocked(groupID string) {
	b, ok := s.state.NodeGroupGuardBindings[groupID]
	s.invalidateGuardBindingsForNodeGroupLocked(groupID, ok && len(b.SecurityGroupIDs) > 0)
}

func guardRulesReferenceGroup(rules []model.GuardRule, groupID string) bool {
	for _, rule := range rules {
		if rule.Remote.Kind == model.NetRefGroup && rule.Remote.GroupID == groupID {
			return true
		}
	}
	return false
}
