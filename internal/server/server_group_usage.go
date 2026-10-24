package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

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
	// among what it applies to, "remote" when a rule points at the group.
	Role string `json:"role"`
}

const groupUseOutboundPolicy = "outbound_policy"

// groupUseSource is one kind of object that can name a node group, with the
// scope that reveals it. Checks (design 32 S2b), security-group bindings (S4)
// and mesh membership rules (design 13 W1) add a source here when they start
// storing group references; the console already renders all four kinds.
type groupUseSource struct {
	kind    string
	scope   string
	collect func(s *Server, groupID string) []groupUse
}

var groupUseSources = []groupUseSource{
	{kind: groupUseOutboundPolicy, scope: "netpolicy:read", collect: (*Server).outboundPolicyGroupUses},
}

func (s *Server) outboundPolicyGroupUses(groupID string) []groupUse {
	names := groupNamesOf(s.store.Groups())
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
		out = append(out, groupUse{Kind: groupUseOutboundPolicy, ID: gp.ID, Label: outboundPolicyLabel(gp, names), Role: role})
	}
	return out
}

// groupUses lists every object that names the group, sorted by kind, then
// label. visible decides which kinds are listed; the rest are counted.
func (s *Server) groupUses(groupID string, visible func(scope string) bool) (uses []groupUse, hidden int) {
	uses = make([]groupUse, 0)
	for _, source := range groupUseSources {
		found := source.collect(s, groupID)
		if visible != nil && !visible(source.scope) {
			hidden += len(found)
			continue
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
	uses, hidden := s.groupUses(groupID, func(scope string) bool {
		return rbac.Allows(p.Principal, scope, "")
	})
	writeJSON(w, http.StatusOK, map[string]any{"group_id": groupID, "used_by": uses, "hidden": hidden})
}

// groupInUseMessage is the sentence a refused group delete answers with. It
// names every user; the deleter holds group:admin and the policy names are
// listable under netpolicy:read, and naming them is what lets the operator
// act on the refusal.
func (s *Server) groupInUseMessage(groupID string, inUse *store.GroupInUseError) string {
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
	uses, _ := s.groupUses(groupID, nil)
	for _, use := range uses {
		parts = append(parts, fmt.Sprintf("%s %q (%s)", groupUseNoun(use.Kind), use.Label, use.Role))
	}
	if len(parts) == 0 {
		return inUse.Error()
	}
	return fmt.Sprintf("node group %q is in use, so it was not deleted: %s. Reparent the children and change or delete the rest first.", name, strings.Join(parts, ", "))
}

func groupUseNoun(kind string) string {
	switch kind {
	case groupUseOutboundPolicy:
		return "outbound policy"
	default:
		return strings.ReplaceAll(kind, "_", " ")
	}
}
