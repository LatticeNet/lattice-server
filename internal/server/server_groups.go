package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// Grouping (iter-063, Phase 1). A Group is a first-class organizational entity.
// Explicit Members are the canonical membership used by policy (Phase 2); an
// optional Selector contributes additional members for DISPLAY only. The agent
// never learns about groups — expansion happens server-side before compilation.

const (
	// groupMaxNestDepth bounds parent chains so the tree stays renderable and
	// cycle checks terminate.
	groupMaxNestDepth = 5
	// groupMaxName / groupMaxDescription clamp free text.
	groupMaxName        = 64
	groupMaxDescription = 280
)

// groupSlugRe is url/nft-safe: lowercase alnum with internal hyphens, 1-40 chars.
var groupSlugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

// groupColorTokens is the allowlist of Tailwind color tokens a group may use.
// Storing a token name (not raw hex) keeps the dashboard CSP class-based.
var groupColorTokens = []string{
	"slate", "sky", "violet", "emerald", "amber", "rose",
	"teal", "cyan", "indigo", "fuchsia", "lime", "orange",
}

func groupColorAllowed(c string) bool {
	for _, t := range groupColorTokens {
		if t == c {
			return true
		}
	}
	return false
}

type groupRollup struct {
	Total    int `json:"total"`
	Online   int `json:"online"`
	Offline  int `json:"offline"`
	Disabled int `json:"disabled"`
}

// groupView is a Group plus its server-resolved membership and a health rollup.
// The embedded Group carries the explicit Members (for editing); ResolvedMembers
// is Members ∪ selector matches (for display/counts).
type groupView struct {
	model.Group
	ResolvedMembers []string    `json:"resolved_members"`
	Rollup          groupRollup `json:"rollup"`
}

func rollupFor(memberIDs []string, byID map[string]model.Node) (groupRollup, []string) {
	var r groupRollup
	resolved := make([]string, 0, len(memberIDs))
	for _, nid := range memberIDs {
		n, ok := byID[nid]
		if !ok {
			continue // membership referencing a deleted node is skipped, not counted
		}
		resolved = append(resolved, nid)
		r.Total++
		if n.Disabled {
			r.Disabled++
		}
		if n.Online {
			r.Online++
		} else {
			r.Offline++
		}
	}
	return r, resolved
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "group:read") {
			return
		}
		nodes := s.store.Nodes()
		byID := make(map[string]model.Node, len(nodes))
		for _, n := range nodes {
			byID[n.ID] = n
		}
		gs := s.store.Groups()
		resolved := groups.ResolveAll(gs, nodes)
		views := make([]groupView, 0, len(gs))
		grouped := make(map[string]bool, len(nodes))
		for _, g := range gs {
			rollup, rm := rollupFor(resolved[g.ID], byID)
			for _, nid := range rm {
				grouped[nid] = true
			}
			views = append(views, groupView{Group: g, ResolvedMembers: rm, Rollup: rollup})
		}
		// Deterministic display order: by parent, then weight, then name.
		sort.SliceStable(views, func(i, j int) bool {
			if views[i].ParentID != views[j].ParentID {
				return views[i].ParentID < views[j].ParentID
			}
			if views[i].Order != views[j].Order {
				return views[i].Order < views[j].Order
			}
			return strings.ToLower(views[i].Name) < strings.ToLower(views[j].Name)
		})
		ungroupedIDs := make([]string, 0)
		for _, n := range nodes {
			if !grouped[n.ID] {
				ungroupedIDs = append(ungroupedIDs, n.ID)
			}
		}
		sort.Strings(ungroupedIDs)
		ur, _ := rollupFor(ungroupedIDs, byID)
		writeJSON(w, http.StatusOK, map[string]any{
			"groups": views,
			"ungrouped": map[string]any{
				"resolved_members": ungroupedIDs,
				"rollup":           ur,
			},
		})
	case http.MethodPost:
		if !s.requireScope(w, p, "group:admin") {
			return
		}
		var req model.Group
		if !decodeClientJSON(w, r, &req) {
			return
		}
		view, err := s.upsertGroup(req, p)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// upsertGroup validates and persists a group (create when ID is empty, else
// update), returning its view. System and CreatedAt are server-owned and cannot
// be set by the client; Slug is immutable after creation.
func (s *Server) upsertGroup(req model.Group, p principal) (groupView, error) {
	nodes := s.store.Nodes()
	byNode := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byNode[n.ID] = n
	}
	existing := s.store.Groups()
	byGroup := make(map[string]model.Group, len(existing))
	for _, g := range existing {
		byGroup[g.ID] = g
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return groupView{}, errors.New("name is required")
	}
	if len(req.Name) > groupMaxName {
		return groupView{}, fmt.Errorf("name must be at most %d characters", groupMaxName)
	}
	req.Description = clampPrintable(strings.TrimSpace(req.Description), groupMaxDescription)
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if !groupSlugRe.MatchString(req.Slug) {
		return groupView{}, errors.New("slug must be lowercase alphanumeric with internal hyphens (1-40 chars)")
	}
	if req.Color == "" {
		req.Color = "slate"
	}
	if !groupColorAllowed(req.Color) {
		return groupView{}, fmt.Errorf("color %q is not an allowed token", req.Color)
	}
	req.Icon = strings.TrimSpace(req.Icon)

	var prior model.Group
	creating := strings.TrimSpace(req.ID) == ""
	if creating {
		req.ID = id.New("grp")
		req.System = false
		req.CreatedAt = time.Time{}
	} else {
		var ok bool
		prior, ok = byGroup[req.ID]
		if !ok {
			return groupView{}, fmt.Errorf("group %q not found", req.ID)
		}
		// Slug is immutable; System and CreatedAt are server-owned.
		req.Slug = prior.Slug
		req.System = prior.System
		req.CreatedAt = prior.CreatedAt
	}

	// Slug uniqueness across other groups.
	for _, g := range existing {
		if g.ID != req.ID && g.Slug == req.Slug {
			return groupView{}, fmt.Errorf("slug %q is already used by group %q", req.Slug, g.ID)
		}
	}

	// Parent existence + cycle/depth.
	req.ParentID = strings.TrimSpace(req.ParentID)
	if req.ParentID != "" {
		if req.ParentID == req.ID {
			return groupView{}, errors.New("a group cannot be its own parent")
		}
		// Reflect the candidate parent into the map so the cycle walk sees it.
		byGroup[req.ID] = model.Group{ID: req.ID, ParentID: req.ParentID}
		if err := groupCycleOK(req.ID, byGroup); err != nil {
			return groupView{}, err
		}
	}

	// Explicit members: dedupe and drop references to non-existent nodes.
	req.Members = dedupeExistingNodes(req.Members, byNode)

	// Leader: if set, it must be an explicit member of the group. The explicit
	// Members list is the canonical membership, so a leader that is only a
	// selector match (display-only) is rejected — a leader has to be a real,
	// policy-relevant member.
	req.LeaderID = strings.TrimSpace(req.LeaderID)
	if req.LeaderID != "" {
		isMember := false
		for _, m := range req.Members {
			if m == req.LeaderID {
				isMember = true
				break
			}
		}
		if !isMember {
			return groupView{}, errors.New("leader_id must be an explicit member of the group")
		}
	}

	// Selector: trim entries; nil out an empty selector so omitempty round-trips.
	req.Selector = normalizeGroupSelector(req.Selector)

	if err := s.store.UpsertGroup(req); err != nil {
		return groupView{}, err
	}
	stored, _ := s.store.Group(req.ID)

	action := "group.update"
	if creating {
		action = "group.create"
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   action,
		Scope:    "group:admin",
		Metadata: map[string]string{"group_id": stored.ID, "slug": stored.Slug},
	})

	resolved := groups.ResolveMembers(stored, nodes)
	rollup, rm := rollupFor(resolved, byNode)
	return groupView{Group: stored, ResolvedMembers: rm, Rollup: rollup}, nil
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if err := s.store.DeleteGroup(req.ID); err != nil {
		// Store rejects delete when the group has children or is policy-referenced.
		writeError(w, http.StatusConflict, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "group.delete",
		Scope:    "group:admin",
		Metadata: map[string]string{"group_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleReorderGroups(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		Items []struct {
			ID       string `json:"id"`
			ParentID string `json:"parent_id"`
			Order    int    `json:"order"`
		} `json:"items"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("items is required"))
		return
	}
	byGroup := make(map[string]model.Group)
	for _, g := range s.store.Groups() {
		byGroup[g.ID] = g
	}
	// Apply the proposed changes to an in-memory copy, then validate every
	// changed group for cycles/depth before persisting anything.
	changed := make([]model.Group, 0, len(req.Items))
	for _, item := range req.Items {
		g, ok := byGroup[item.ID]
		if !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("group %q not found", item.ID))
			return
		}
		g.ParentID = strings.TrimSpace(item.ParentID)
		g.Order = item.Order
		byGroup[g.ID] = g
		changed = append(changed, g)
	}
	for _, g := range changed {
		if g.ParentID == g.ID {
			writeError(w, http.StatusBadRequest, errors.New("a group cannot be its own parent"))
			return
		}
		if g.ParentID != "" {
			if _, ok := byGroup[g.ParentID]; !ok {
				writeError(w, http.StatusBadRequest, fmt.Errorf("parent group %q not found", g.ParentID))
				return
			}
		}
		if err := groupCycleOK(g.ID, byGroup); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	for _, g := range changed {
		if err := s.store.UpsertGroup(g); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "group.reorder",
		Scope:    "group:admin",
		Metadata: map[string]string{"count": fmt.Sprintf("%d", len(changed))},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		GroupID string   `json:"group_id"`
		Add     []string `json:"add"`
		Remove  []string `json:"remove"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.GroupID = strings.TrimSpace(req.GroupID)
	g, ok := s.store.Group(req.GroupID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("group not found"))
		return
	}
	remove := make(map[string]bool, len(req.Remove))
	for _, nid := range req.Remove {
		remove[strings.TrimSpace(nid)] = true
	}
	members := make([]string, 0, len(g.Members)+len(req.Add))
	members = append(members, g.Members...)
	members = append(members, req.Add...)
	kept := members[:0]
	for _, nid := range members {
		nid = strings.TrimSpace(nid)
		if nid != "" && !remove[nid] {
			kept = append(kept, nid)
		}
	}
	nodes := s.store.Nodes()
	byNode := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byNode[n.ID] = n
	}
	g.Members = dedupeExistingNodes(kept, byNode)
	// Keep the leader invariant: a leader must be an explicit member, so drop a
	// dangling LeaderID when that node is no longer a member.
	if g.LeaderID != "" {
		stillMember := false
		for _, m := range g.Members {
			if m == g.LeaderID {
				stillMember = true
				break
			}
		}
		if !stillMember {
			g.LeaderID = ""
		}
	}
	if err := s.store.UpsertGroup(g); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	stored, _ := s.store.Group(g.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "group.members",
		Scope:    "group:admin",
		Metadata: map[string]string{"group_id": stored.ID},
	})
	resolved := groups.ResolveMembers(stored, nodes)
	rollup, rm := rollupFor(resolved, byNode)
	writeJSON(w, http.StatusOK, groupView{Group: stored, ResolvedMembers: rm, Rollup: rollup})
}

// handleGroupPreview resolves a selector against the current fleet without
// persisting anything, so the editor can show "matches N nodes" live.
func (s *Server) handleGroupPreview(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var sel model.GroupSelector
	if !decodeClientJSON(w, r, &sel) {
		return
	}
	nodes := s.store.Nodes()
	ids := groups.ResolveMembers(model.Group{Selector: normalizeGroupSelector(&sel)}, nodes)
	writeJSON(w, http.StatusOK, map[string]any{"node_ids": ids, "count": len(ids)})
}

// handleGroupSeed idempotently creates display groups from existing node roles
// and popular tags. It never overwrites or deletes; a slug that already exists
// is skipped. This is an explicit operator action (not a silent on-load
// migration) so a deploy never mutates production grouping by surprise.
func (s *Server) handleGroupSeed(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodes := s.store.Nodes()
	existingSlugs := make(map[string]bool)
	for _, g := range s.store.Groups() {
		existingSlugs[g.Slug] = true
	}

	roleCount := map[string]int{}
	tagCount := map[string]int{}
	for _, n := range nodes {
		if role := strings.TrimSpace(n.Role); role != "" {
			roleCount[role]++
		}
		seen := map[string]bool{}
		for _, t := range n.Tags {
			t = strings.TrimSpace(t)
			if t != "" && !seen[t] {
				seen[t] = true
				tagCount[t]++
			}
		}
	}

	type seed struct {
		name, slug string
		sel        model.GroupSelector
	}
	seeds := make([]seed, 0)
	for role := range roleCount {
		seeds = append(seeds, seed{
			name: "Role: " + role,
			slug: "role-" + slugify(role),
			sel:  model.GroupSelector{MatchRoles: []string{role}},
		})
	}
	for tag, n := range tagCount {
		if n < 2 { // only tags shared by 2+ nodes become groups
			continue
		}
		seeds = append(seeds, seed{
			name: "Tag: " + tag,
			slug: "tag-" + slugify(tag),
			sel:  model.GroupSelector{MatchTagsAny: []string{tag}},
		})
	}
	sort.Slice(seeds, func(i, j int) bool { return seeds[i].slug < seeds[j].slug })

	created, skipped := 0, 0
	for i, sd := range seeds {
		if sd.slug == "" || existingSlugs[sd.slug] || !groupSlugRe.MatchString(sd.slug) {
			skipped++
			continue
		}
		g := model.Group{
			ID:       id.New("grp"),
			Name:     sd.name,
			Slug:     sd.slug,
			Color:    groupColorTokens[i%len(groupColorTokens)],
			Order:    i,
			Selector: &sd.sel,
		}
		if err := s.store.UpsertGroup(g); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		existingSlugs[sd.slug] = true
		created++
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "group.seed",
		Scope:    "group:admin",
		Metadata: map[string]string{"created": fmt.Sprintf("%d", created), "skipped": fmt.Sprintf("%d", skipped)},
	})
	writeJSON(w, http.StatusOK, map[string]int{"created": created, "skipped": skipped})
}

// groupCycleOK walks the parent chain of groupID and fails on a revisit (cycle)
// or when the chain exceeds groupMaxNestDepth. byGroup must already reflect any
// candidate ParentID change being validated.
func groupCycleOK(groupID string, byGroup map[string]model.Group) error {
	seen := map[string]bool{}
	cur := groupID
	for depth := 0; cur != ""; depth++ {
		if seen[cur] {
			return errors.New("group parent assignment would create a cycle")
		}
		if depth > groupMaxNestDepth {
			return fmt.Errorf("group nesting exceeds max depth %d", groupMaxNestDepth)
		}
		seen[cur] = true
		g, ok := byGroup[cur]
		if !ok {
			return fmt.Errorf("parent group %q not found", cur)
		}
		cur = strings.TrimSpace(g.ParentID)
	}
	return nil
}

func dedupeExistingNodes(in []string, byNode map[string]model.Node) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, nid := range in {
		nid = strings.TrimSpace(nid)
		if nid == "" || seen[nid] {
			continue
		}
		if _, ok := byNode[nid]; !ok {
			continue // silently drop a reference to a node that no longer exists
		}
		seen[nid] = true
		out = append(out, nid)
	}
	sort.Strings(out)
	return out
}

// normalizeGroupSelector trims entries and returns nil for an empty selector so
// JSON omitempty round-trips and the resolver treats it as "no selector".
func normalizeGroupSelector(sel *model.GroupSelector) *model.GroupSelector {
	if sel == nil {
		return nil
	}
	out := model.GroupSelector{
		MatchTagsAny:   trimNonEmpty(sel.MatchTagsAny),
		MatchRoles:     trimNonEmpty(sel.MatchRoles),
		MatchCountry:   trimNonEmpty(sel.MatchCountry),
		MatchContinent: trimNonEmpty(sel.MatchContinent),
	}
	if len(out.MatchTagsAny) == 0 && len(out.MatchRoles) == 0 &&
		len(out.MatchCountry) == 0 && len(out.MatchContinent) == 0 {
		return nil
	}
	return &out
}

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// slugify lowercases and replaces runs of non-[a-z0-9] with a single hyphen,
// trims leading/trailing hyphens, and clamps to 40 chars.
func slugify(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	prevDash := false
	for _, c := range in {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	return out
}
