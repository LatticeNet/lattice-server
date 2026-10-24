package store

import (
	"fmt"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// GroupInUseError is DeleteGroup's refusal: the group still has children or
// outbound policies still name it. The ids are sorted.
type GroupInUseError struct {
	GroupID   string
	ChildIDs  []string
	PolicyIDs []string
}

func (e *GroupInUseError) Error() string {
	parts := make([]string, 0, 2)
	if len(e.ChildIDs) > 0 {
		parts = append(parts, "child group "+strings.Join(e.ChildIDs, ", "))
	}
	if len(e.PolicyIDs) > 0 {
		parts = append(parts, "group policy "+strings.Join(e.PolicyIDs, ", "))
	}
	return fmt.Sprintf("group %q is in use by %s; reparent the children and change or delete the policies first", e.GroupID, strings.Join(parts, " and "))
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

// groupInUse is the shared in-use test of both state stores.
func groupInUse(id string, groups []model.Group, policies []model.GroupNetPolicy) error {
	inUse := &GroupInUseError{GroupID: id}
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
	if len(inUse.ChildIDs) == 0 && len(inUse.PolicyIDs) == 0 {
		return nil
	}
	sort.Strings(inUse.ChildIDs)
	sort.Strings(inUse.PolicyIDs)
	return inUse
}
