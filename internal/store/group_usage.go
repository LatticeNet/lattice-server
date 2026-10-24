package store

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// GroupInUseError is DeleteGroup's refusal: the group still has children, or
// outbound policies, check definitions or NetGuard records still name it.
// The ids are sorted.
type GroupInUseError struct {
	GroupID            string
	ChildIDs           []string
	PolicyIDs          []string
	CheckDefinitionIDs []string
	// GuardBinding is true when the group binds security groups (S4).
	GuardBinding bool
	// SecurityGroupIDs have a rule whose remote is the group, and
	// GuardOverrideNodeIDs a binding override that does.
	SecurityGroupIDs     []string
	GuardOverrideNodeIDs []string
}

func (e *GroupInUseError) Error() string {
	parts := make([]string, 0, 3)
	if len(e.ChildIDs) > 0 {
		parts = append(parts, "child group "+strings.Join(e.ChildIDs, ", "))
	}
	if len(e.PolicyIDs) > 0 {
		parts = append(parts, "group policy "+strings.Join(e.PolicyIDs, ", "))
	}
	if len(e.CheckDefinitionIDs) > 0 {
		parts = append(parts, "check definition "+strings.Join(e.CheckDefinitionIDs, ", "))
	}
	if e.GuardBinding {
		parts = append(parts, "its security-group binding")
	}
	if len(e.SecurityGroupIDs) > 0 {
		parts = append(parts, "security group "+strings.Join(e.SecurityGroupIDs, ", "))
	}
	if len(e.GuardOverrideNodeIDs) > 0 {
		parts = append(parts, "the guard binding of node "+strings.Join(e.GuardOverrideNodeIDs, ", "))
	}
	return fmt.Sprintf("group %q is in use by %s; reparent the children and change or delete the rest first", e.GroupID, strings.Join(parts, " and "))
}

// groupGuardUses is what NetGuard holds that names a node group: the
// group's own security-group binding, and rules whose remote is the group.
// Only the JSON state store holds NetGuard records; the bolt one passes the
// zero value.
type groupGuardUses struct {
	binding          bool
	securityGroupIDs []string
	overrideNodeIDs  []string
}

// guardUsesOfGroupLocked collects groupGuardUses from the live state.
func (s *Store) guardUsesOfGroupLocked(groupID string) groupGuardUses {
	var uses groupGuardUses
	if b, ok := s.state.NodeGroupGuardBindings[groupID]; ok && len(b.SecurityGroupIDs) > 0 {
		uses.binding = true
	}
	for id, sg := range s.state.SecurityGroups {
		if guardRulesReferenceGroup(sg.Rules, groupID) {
			uses.securityGroupIDs = append(uses.securityGroupIDs, id)
		}
	}
	for nodeID, binding := range s.state.GuardBindings {
		if guardRulesReferenceGroup(binding.Overrides, groupID) {
			uses.overrideNodeIDs = append(uses.overrideNodeIDs, nodeID)
		}
	}
	return uses
}

// GroupPolicyNamesGroup reports whether an outbound policy names a node
// group, as one of its targets or as the remote of any rule.
func GroupPolicyNamesGroup(gp model.GroupNetPolicy, groupID string) bool {
	for _, g := range gp.TargetScope().Groups {
		if g == groupID {
			return true
		}
	}
	for _, rule := range gp.Rules {
		if rule.Remote.Kind == model.NetRefGroup && rule.Remote.GroupID == groupID {
			return true
		}
	}
	return false
}

// CheckDefinitionNamesGroup reports whether a check definition names a node
// group among its sources and among its targets.
func CheckDefinitionNamesGroup(def model.CheckDefinition, groupID string) (source, target bool) {
	return slices.Contains(def.Sources.Groups, groupID), slices.Contains(def.Targets.Groups, groupID)
}

// groupInUse is the shared in-use test of both state stores.
func groupInUse(id string, groups []model.Group, policies []model.GroupNetPolicy, defs []model.CheckDefinition, guard groupGuardUses) error {
	inUse := &GroupInUseError{GroupID: id, GuardBinding: guard.binding,
		SecurityGroupIDs: guard.securityGroupIDs, GuardOverrideNodeIDs: guard.overrideNodeIDs}
	for _, child := range groups {
		if child.ParentID == id {
			inUse.ChildIDs = append(inUse.ChildIDs, child.ID)
		}
	}
	for _, gp := range policies {
		if GroupPolicyNamesGroup(gp, id) {
			inUse.PolicyIDs = append(inUse.PolicyIDs, gp.ID)
		}
	}
	for _, def := range defs {
		if source, target := CheckDefinitionNamesGroup(def, id); source || target {
			inUse.CheckDefinitionIDs = append(inUse.CheckDefinitionIDs, def.ID)
		}
	}
	if len(inUse.ChildIDs) == 0 && len(inUse.PolicyIDs) == 0 && len(inUse.CheckDefinitionIDs) == 0 &&
		!inUse.GuardBinding && len(inUse.SecurityGroupIDs) == 0 && len(inUse.GuardOverrideNodeIDs) == 0 {
		return nil
	}
	sort.Strings(inUse.ChildIDs)
	sort.Strings(inUse.PolicyIDs)
	sort.Strings(inUse.CheckDefinitionIDs)
	sort.Strings(inUse.SecurityGroupIDs)
	sort.Strings(inUse.GuardOverrideNodeIDs)
	return inUse
}
