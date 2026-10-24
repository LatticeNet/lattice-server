package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// --- Node group Used by (design 32 D3) ---

// groupUse is one object that names a node group.
type groupUse struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
	// Role says how the object names the group: "target" when the group is
	// among what it applies to, "remote" when a policy rule points at the
	// group, "source" when a check runs from it, and "source_and_target"
	// when a check runs from the group and to it, as a group mesh does.
	Role string `json:"role"`
}

const (
	groupUseOutboundPolicy       = "outbound_policy"
	groupUseCheck                = "check"
	groupUseSecurityGroupBinding = "security_group_binding"
)

// groupUseSource is one kind of object that can name a node group, with the
// scope that reveals it. Checks (design 32 S2b), security-group bindings (S4)
// and mesh membership rules (design 13 W1) add a source here when they start
// storing group references; the console already renders all four kinds.
// collect builds labels for viewer, or for the system when viewer is nil, and
// counts the uses of its kind that viewer may not see one by one even with the
// kind's scope.
type groupUseSource struct {
	kind    string
	scope   string
	collect func(s *Server, groupID string, viewer *principal) (uses []groupUse, hidden int)
}

var groupUseSources = []groupUseSource{
	{kind: groupUseCheck, scope: "monitor:read", collect: (*Server).checkDefinitionGroupUses},
	{kind: groupUseOutboundPolicy, scope: "netpolicy:read", collect: (*Server).outboundPolicyGroupUses},
	{kind: groupUseSecurityGroupBinding, scope: "netguard:read", collect: (*Server).securityGroupBindingGroupUses},
}

// securityGroupBindingGroupUses lists what NetGuard holds that names the
// group (S4): each security group its binding applies to its members, as
// target, and each security group or node binding whose rules take the
// group as a remote, as remote. NetGuard's catalogue is read by an
// unrestricted principal only (requireGlobalNetGuardScope), so a viewer
// confined to some nodes is given the count.
func (s *Server) securityGroupBindingGroupUses(groupID string, viewer *principal) ([]groupUse, int) {
	out := make([]groupUse, 0)
	if b, ok := s.store.NodeGroupGuardBinding(groupID); ok {
		for _, sgID := range b.SecurityGroupIDs {
			label := sgID
			if sg, ok := s.store.SecurityGroup(sgID); ok && sg.Name != "" {
				label = sg.Name
			}
			out = append(out, groupUse{Kind: groupUseSecurityGroupBinding, ID: sgID, Label: label, Role: "target"})
		}
	}
	for _, sg := range s.store.SecurityGroups() {
		if guardRulesNameNodeGroup(sg.Rules, groupID) {
			out = append(out, groupUse{Kind: groupUseSecurityGroupBinding, ID: sg.ID, Label: sg.Name, Role: "remote"})
		}
	}
	for _, binding := range s.store.NodeGuardBindings() {
		if guardRulesNameNodeGroup(binding.Overrides, groupID) {
			name := s.nodeName(binding.NodeID)
			if name == "" {
				name = binding.NodeID
			}
			out = append(out, groupUse{Kind: groupUseSecurityGroupBinding, ID: binding.NodeID, Label: "override on " + name, Role: "remote"})
		}
	}
	if viewer != nil && principalHasNodeRestriction(*viewer) {
		return []groupUse{}, len(out)
	}
	return out, 0
}

func guardRulesNameNodeGroup(rules []model.GuardRule, groupID string) bool {
	for _, rule := range rules {
		if rule.Remote.Kind == model.NetRefGroup && rule.Remote.GroupID == groupID {
			return true
		}
	}
	return false
}

// checkDefinitionGroupUses lists the check definitions (design 32 D1) that
// name the group among their sources or targets, by name. A definition the
// viewer may not read (checkDefinitionVisible: a confined viewer never reads
// one that names a group) is counted instead.
func (s *Server) checkDefinitionGroupUses(groupID string, viewer *principal) ([]groupUse, int) {
	out := make([]groupUse, 0)
	hidden := 0
	for _, def := range s.store.CheckDefinitions() {
		source, target := store.CheckDefinitionNamesGroup(def, groupID)
		if !source && !target {
			continue
		}
		if viewer != nil && !checkDefinitionVisible(*viewer, def) {
			hidden++
			continue
		}
		role := "target"
		switch {
		case source && target:
			role = "source_and_target"
		case source:
			role = "source"
		}
		out = append(out, groupUse{Kind: groupUseCheck, ID: def.ID, Label: def.Name, Role: role})
	}
	return out, hidden
}

func (s *Server) outboundPolicyGroupUses(groupID string, viewer *principal) ([]groupUse, int) {
	names, nodeNames := groupNamesOf(s.store.Groups()), nodeNamesOf(s.store.Nodes())
	out := make([]groupUse, 0)
	for _, gp := range s.store.GroupPolicies() {
		if !store.GroupPolicyNamesGroup(gp, groupID) {
			continue
		}
		role := "remote"
		for _, g := range gp.TargetScope().Groups {
			if g == groupID {
				role = "target"
			}
		}
		target, hidden := gp.TargetScope(), 0
		if viewer != nil {
			target, hidden = viewerTarget(*viewer, target)
		}
		out = append(out, groupUse{Kind: groupUseOutboundPolicy, ID: gp.ID, Label: outboundPolicyLabel(gp.Name, target, hidden, names, nodeNames), Role: role})
	}
	return out, 0
}

// groupUses lists every object that names the group, sorted by kind, then
// label. For a viewer, a kind it lacks the read scope for is counted, not
// listed, and labels leave out nodes it cannot read; a nil viewer is the
// system and sees everything.
func (s *Server) groupUses(groupID string, viewer *principal) (uses []groupUse, hidden map[string]int) {
	uses = make([]groupUse, 0)
	hidden = make(map[string]int)
	for _, source := range groupUseSources {
		if viewer != nil && !rbac.Allows(viewer.Principal, source.scope, "") {
			found, unseen := source.collect(s, groupID, nil)
			if n := len(found) + unseen; n > 0 {
				hidden[source.kind] += n
			}
			continue
		}
		found, unseen := source.collect(s, groupID, viewer)
		if unseen > 0 {
			hidden[source.kind] += unseen
		}
		uses = append(uses, found...)
	}
	sort.SliceStable(uses, func(i, j int) bool {
		if uses[i].Kind != uses[j].Kind {
			return uses[i].Kind < uses[j].Kind
		}
		if uses[i].Label != uses[j].Label {
			return uses[i].Label < uses[j].Label
		}
		return uses[i].ID < uses[j].ID
	})
	return uses, hidden
}

// handleGroupUsedBy answers GET /api/groups/used-by?id=<group>: every object
// that names the group, each listed only when the caller holds the scope that
// reads that kind of object; the rest are counted in hidden.
func (s *Server) handleGroupUsedBy(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	groupID := strings.TrimSpace(r.URL.Query().Get("id"))
	if groupID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if _, ok := s.store.Group(groupID); !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("node group %q not found", groupID))
		return
	}
	uses, hidden := s.groupUses(groupID, &p)
	total := 0
	for _, n := range hidden {
		total += n
	}
	writeJSON(w, http.StatusOK, map[string]any{"group_id": groupID, "used_by": uses, "hidden": total})
}

// groupInUseMessage is the sentence a refused group delete answers with. It
// names every user the deleter may read, as the Used by list would show it to
// them, and counts the kinds it may not, so the refusal says why without
// naming what the deleter cannot see.
func (s *Server) groupInUseMessage(p principal, groupID string, inUse *store.GroupInUseError) string {
	name := groupID
	if g, ok := s.store.Group(groupID); ok && g.Name != "" {
		name = g.Name
	}
	parts := make([]string, 0, len(inUse.ChildIDs)+len(inUse.PolicyIDs))
	for _, childID := range inUse.ChildIDs {
		label := childID
		if g, ok := s.store.Group(childID); ok && g.Name != "" {
			label = g.Name
		}
		parts = append(parts, fmt.Sprintf("child group %q", label))
	}
	uses, hidden := s.groupUses(groupID, &p)
	for _, use := range uses {
		parts = append(parts, fmt.Sprintf("%s %q (%s)", groupUseNoun(use.Kind, 1), use.Label, strings.ReplaceAll(use.Role, "_", " ")))
	}
	kinds := make([]string, 0, len(hidden))
	for kind := range hidden {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		parts = append(parts, fmt.Sprintf("%d %s you cannot read", hidden[kind], groupUseNoun(kind, hidden[kind])))
	}
	if len(parts) == 0 {
		return inUse.Error()
	}
	next := "Change or delete them first."
	if len(inUse.ChildIDs) > 0 {
		next = "Reparent the child groups and change or delete the rest first."
	}
	return fmt.Sprintf("node group %q is in use, so it was not deleted: %s. %s", name, strings.Join(parts, ", "), next)
}

func groupUseNoun(kind string, n int) string {
	switch kind {
	case groupUseOutboundPolicy:
		if n != 1 {
			return "outbound policies"
		}
		return "outbound policy"
	case groupUseCheck:
		if n != 1 {
			return "check definitions"
		}
		return "check definition"
	case groupUseSecurityGroupBinding:
		if n != 1 {
			return "security-group bindings"
		}
		return "security-group binding"
	}
	return strings.ReplaceAll(kind, "_", " ")
}
