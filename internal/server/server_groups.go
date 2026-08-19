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
	"github.com/LatticeNet/lattice-server/internal/rbac"
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
// Members is the explicit operator-pinned list (for editing); ResolvedMembers is
// Members ∪ selector matches (for display/counts). Both are narrowed to the
// nodes the reader may see.
//
// Every field is projected by hand, and model.Group is deliberately NOT
// embedded. It used to be, and the embedded Members carried a json tag, so the
// complete explicit membership of every group rode out inside the very response
// whose resolved_members, rollup and ungrouped were being filtered. Embedding a
// model struct in a view means the next field added to the model ships to the
// caller too, and nobody adding that field will be reading this file.
// server_users.go learned the same lesson; see the note above userView.
type groupView struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Slug            string               `json:"slug"`
	Description     string               `json:"description,omitempty"`
	Color           string               `json:"color"`
	Icon            string               `json:"icon,omitempty"`
	ParentID        string               `json:"parent_id,omitempty"`
	Order           int                  `json:"order"`
	Members         []string             `json:"members"`
	Selector        *model.GroupSelector `json:"selector,omitempty"`
	LeaderID        string               `json:"leader_id,omitempty"`
	System          bool                 `json:"system,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
	ResolvedMembers []string             `json:"resolved_members"`
	Rollup          groupRollup          `json:"rollup"`
}

// toGroupView projects a stored group for one reader. It is the only place a
// groupView is built, so the membership narrowing cannot be forgotten at one of
// the four call sites.
//
// Members is filtered rather than refused: this is a listing, and a shorter
// list is a correct answer. LeaderID is dropped when it names a node the reader
// cannot see, for the same reason. upsertGroup preserves both on write, so a
// confined operator editing a group does not delete what was filtered out of
// their copy.
func toGroupView(p principal, g model.Group, resolved []string, rollup groupRollup) groupView {
	view := groupView{
		ID:              g.ID,
		Name:            g.Name,
		Slug:            g.Slug,
		Description:     g.Description,
		Color:           g.Color,
		Icon:            g.Icon,
		ParentID:        g.ParentID,
		Order:           g.Order,
		Members:         readableNodeIDs(p, "group:read", g.Members),
		Selector:        g.Selector,
		System:          g.System,
		CreatedAt:       g.CreatedAt,
		UpdatedAt:       g.UpdatedAt,
		ResolvedMembers: resolved,
		Rollup:          rollup,
	}
	if g.LeaderID != "" && rbac.Allows(p.Principal, "group:read", g.LeaderID) {
		view.LeaderID = g.LeaderID
	}
	return view
}

// unreadableNodeIDs is the complement of readableNodeIDs: the ids p may NOT
// read. Used to carry hidden state across a read-modify-write.
func unreadableNodeIDs(p principal, scope string, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, nodeID := range ids {
		if !rbac.Allows(p.Principal, scope, nodeID) {
			out = append(out, nodeID)
		}
	}
	return out
}

// readableNodes is readableNodeIDs over whole nodes, for the resolve paths.
func readableNodes(p principal, scope string, nodes []model.Node) []model.Node {
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if rbac.Allows(p.Principal, scope, n.ID) {
			out = append(out, n)
		}
	}
	return out
}

// readableNodeIDs keeps the ids in the given order that p may read under scope.
// Always returns a non-nil slice so the JSON is [] rather than null.
func readableNodeIDs(p principal, scope string, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, nodeID := range ids {
		if rbac.Allows(p.Principal, scope, nodeID) {
			out = append(out, nodeID)
		}
	}
	return out
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
		// group:read was a flat scope check, so the allowlist never applied and
		// every caller received the fleet's complete node-id inventory: each
		// group's resolved members plus ungrouped, which is by construction
		// every node not in a group.
		//
		// Filtered at the input, not refused: groups are a listing and a
		// shorter one is a correct answer. Resolving over the whole fleet and
		// hiding rows afterwards would still leak through the rollup counts.
		nodes := make([]model.Node, 0)
		for _, n := range s.store.Nodes() {
			if rbac.Allows(p.Principal, "group:read", n.ID) {
				nodes = append(nodes, n)
			}
		}
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
			views = append(views, toGroupView(p, g, rm, rollup))
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
		// group:admin was a flat scope check here, so the allowlist never
		// applied and a caller confined to one node could pin any node into
		// any group. Membership drives ExpandGroupPolicies, so that decided
		// which fleet firewall policy applied to nodes the caller cannot
		// administer, and the echoed member list doubled as an existence
		// oracle because dedupeExistingNodes silently drops ids that do not
		// exist. handleGroupMembers already refuses this; the same helper and
		// the same reasoning belong on the sibling that creates and updates.
		//
		// Refused rather than filtered, and for the reason written there:
		// quietly dropping the members the caller may not touch would report
		// success for an edit that did not happen.
		if !s.requireReadableNodes(w, p, "group:admin", "this group", req.Members) {
			return
		}
		if req.LeaderID != "" && !s.requireReadableNodes(w, p, "group:admin", "this leader", []string{req.LeaderID}) {
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

	// A confined operator reads a filtered copy of this group (toGroupView
	// narrows Members), so a plain read-modify-write would delete the members
	// they were never shown. Carry the stored members they cannot see back in.
	// The handler has already refused any member they named but may not touch,
	// so what survives here is exactly: what they may edit, as they left it,
	// plus what they may not edit, untouched.
	if !creating {
		if prior, ok := byGroup[req.ID]; ok {
			req.Members = append(req.Members, unreadableNodeIDs(p, "group:admin", prior.Members)...)
			req.Members = dedupeExistingNodes(req.Members, byNode)
		}
	}

	// Leader: if set, it must be an explicit member of the group. Selectors are
	// dynamic and can change as node facts change, so a leader must be pinned by
	// the operator rather than inferred from selector membership.
	req.LeaderID = strings.TrimSpace(req.LeaderID)
	// Same preservation for the leader: it is filtered out of a confined
	// operator's copy, so an empty submission from them means "unchanged", not
	// "cleared". An operator who can see the leader can still clear it.
	if req.LeaderID == "" && !creating {
		if prior, ok := byGroup[req.ID]; ok && prior.LeaderID != "" &&
			!rbac.Allows(p.Principal, "group:admin", prior.LeaderID) {
			req.LeaderID = prior.LeaderID
		}
	}
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

	// Resolved over the caller's readable nodes, not the fleet. Resolving a
	// caller-supplied selector over every node and echoing the matches is the
	// query engine handleGroupPreview was rewritten to stop being: name a
	// country or a tag, read back which nodes matched.
	readable := readableNodes(p, "group:read", nodes)
	resolved := groups.ResolveMembers(stored, readable)
	rollup, rm := rollupFor(resolved, byNode)
	return toGroupView(p, stored, rm, rollup), nil
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
	// group_id arrives in the body, so withAuth's ?node_id check never fired
	// and no node in add or remove was ever authorized. Group membership drives
	// ExpandGroupPolicies, so an operator scoped to one node could move any
	// node into or out of any group and thereby change which fleet-wide
	// firewall policy applies to it. dedupeExistingNodes silently dropping ids
	// that do not exist made the echoed member list an existence oracle too.
	//
	// Refused rather than filtered: silently ignoring the members the caller
	// may not touch would report success for an edit that did not happen.
	if !s.requireReadableNodes(w, p, "group:admin", "this membership change", append(append([]string{}, req.Add...), req.Remove...)) {
		return
	}
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
	writeJSON(w, http.StatusOK, toGroupView(p, stored, rm, rollup))
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
	// The selector comes from the caller, so resolving it against the whole
	// fleet turned this into a query engine over it: match_country JP or
	// match_tags_any prod enumerated the fleet by geo, role or tag. Resolving
	// against the readable subset answers the editor's real question, which is
	// "how many of the nodes I administer does this match".
	nodes := make([]model.Node, 0)
	for _, n := range s.store.Nodes() {
		if rbac.Allows(p.Principal, "group:read", n.ID) {
			nodes = append(nodes, n)
		}
	}
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
