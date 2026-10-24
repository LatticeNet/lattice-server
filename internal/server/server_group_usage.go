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
// collect builds labels for viewer, or for the system when viewer is nil.
type groupUseSource struct {
	kind    string
	scope   string
	collect func(s *Server, groupID string, viewer *principal) []groupUse
}

var groupUseSources = []groupUseSource{
	{kind: groupUseOutboundPolicy, scope: "netpolicy:read", collect: (*Server).outboundPolicyGroupUses},
}

func (s *Server) outboundPolicyGroupUses(groupID string, viewer *principal) []groupUse {
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
	return out
}

// groupUses lists every object that names the group, sorted by kind, then
// label. For a viewer, a kind it lacks the read scope for is counted, not
// listed, and labels leave out nodes it cannot read; a nil viewer is the
// system and sees everything.
func (s *Server) groupUses(groupID string, viewer *principal) (uses []groupUse, hidden map[string]int) {
	uses = make([]groupUse, 0)
	hidden = make(map[string]int)
	for _, source := range groupUseSources {
		found := source.collect(s, groupID, viewer)
		if viewer != nil && !rbac.Allows(viewer.Principal, source.scope, "") {
			if len(found) > 0 {
				hidden[source.kind] += len(found)
			}
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
		parts = append(parts, fmt.Sprintf("%s %q (%s)", groupUseNoun(use.Kind, 1), use.Label, use.Role))
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
	noun := strings.ReplaceAll(kind, "_", " ")
	if kind == groupUseOutboundPolicy {
		noun = "outbound policy"
		if n != 1 {
			noun = "outbound policies"
		}
	}
	return noun
}
