package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netpolicy"
)

// Group-scoped network policy (iter-063, Phase 2). Operators author intent once
// per group; the server EXPANDS it into per-node model.NetPolicy documents that
// feed the unchanged per-node compile/approval/apply path. The agent never sees
// a group ref.

type groupPolicyView struct {
	model.GroupNetPolicy
	ScopeGroupName string `json:"scope_group_name,omitempty"`
	GroupRuleCount int    `json:"group_rule_count"`
}

func (s *Server) toGroupPolicyView(gp model.GroupNetPolicy) groupPolicyView {
	name := ""
	if g, ok := s.store.Group(gp.ScopeGroupID); ok {
		name = g.Name
	}
	return groupPolicyView{GroupNetPolicy: gp, ScopeGroupName: name, GroupRuleCount: len(gp.Rules)}
}

func (s *Server) handleGroupPolicy(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "netpolicy:read") {
			return
		}
		policies := s.store.GroupPolicies()
		views := make([]groupPolicyView, 0, len(policies))
		for _, gp := range policies {
			views = append(views, s.toGroupPolicyView(gp))
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": views})
	case http.MethodPost:
		if !s.requireScope(w, p, "netpolicy:admin") {
			return
		}
		var req model.GroupNetPolicy
		if !decodeClientJSON(w, r, &req) {
			return
		}
		// A group policy definition expands across its group's nodes at plan
		// time; the per-node apply is gated, but a confined token defining
		// fleet policy is the definition-layer half of the same hole (finding
		// E, 2026-09-01 multi-operator audit). Unlike a capability gate or an
		// SSO provider this write HAS a node dimension, the scope group's
		// membership, so it is confined along it rather than refused outright
		// (the first fix): the caller must hold netpolicy:admin on every node
		// the group resolves to, the reach rule the enroll-time group join
		// already applies. Selector-resolved members count the same as
		// explicit ones, because they are the nodes the definition expands
		// onto at plan time. Membership drift after this check is mediated by
		// writes that carry their own reach checks: group edits take
		// requireReadableNodes, and plan re-authorizes every target node.
		// The reach must cover the policy being OVERWRITTEN as well as the one
		// being written. Checking only the incoming scope group left a takeover
		// open: a confined caller could name an existing policy whose group
		// spans nodes outside its allowlist and re-point it at a group inside,
		// withdrawing policy from nodes it cannot reach without ever being
		// refused. An id that resolves to nothing falls through to
		// upsertGroupPolicy's own not-found answer rather than becoming a
		// second existence probe with different wording.
		reach := s.groupPolicyReach(req.ScopeGroupID)
		if priorID := strings.TrimSpace(req.ID); priorID != "" {
			if prior, ok := s.store.GroupPolicy(priorID); ok {
				reach = append(reach, s.groupPolicyReach(prior.ScopeGroupID)...)
			}
		}
		if !s.requireGroupPolicyReach(w, p, "this group policy", reach) {
			return
		}
		view, err := s.upsertGroupPolicy(req, p)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// groupPolicyReach is the node set a group policy write touches: the scope
// group's resolved membership, explicit and selector alike, at the time of the
// write. An unknown or empty group id resolves to no nodes; the upsert's own
// validation answers for those, so the reach check never becomes a second
// existence probe with different wording.
func (s *Server) groupPolicyReach(groupID string) []string {
	resolved := groups.ResolveAll(s.store.Groups(), s.store.Nodes())
	return resolved[strings.TrimSpace(groupID)]
}

// requireGroupPolicyReach applies the reach rule to a group policy write and,
// for a node-restricted caller, refuses a write that touches no resolvable
// node at all. requireReadableNodes passes an empty set vacuously, because
// nothing in it is denied; without this a confined caller could define or
// withdraw a definition on a group that resolves to no nodes today and gains
// members outside its allowlist tomorrow, which is the same drift the reach
// rule exists to bound. An unrestricted caller keeps the empty case, where
// pre-declaring policy for a group not yet populated is legitimate.
func (s *Server) requireGroupPolicyReach(w http.ResponseWriter, p principal, what string, ids []string) bool {
	if len(ids) == 0 && principalHasNodeRestriction(p) {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "authorize.nodeset",
			Scope:    "netpolicy:admin",
			Decision: "deny",
			Reason:   "scope group resolves to no nodes; a node-restricted token cannot be confined along it",
		})
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied,
			what+" scopes a group that resolves to no nodes, so a token carrying a server allowlist cannot be confined along it"))
		return false
	}
	return s.requireReadableNodes(w, p, "netpolicy:admin", what, ids)
}

func (s *Server) upsertGroupPolicy(req model.GroupNetPolicy, p principal) (groupPolicyView, error) {
	req.ScopeGroupID = strings.TrimSpace(req.ScopeGroupID)
	if req.ScopeGroupID == "" {
		return groupPolicyView{}, errors.New("scope_group_id is required")
	}
	if _, ok := s.store.Group(req.ScopeGroupID); !ok {
		return groupPolicyView{}, fmt.Errorf("scope group %q not found", req.ScopeGroupID)
	}
	for i, rule := range req.Rules {
		if err := s.validateGroupRule(rule); err != nil {
			return groupPolicyView{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	creating := strings.TrimSpace(req.ID) == ""
	if creating {
		req.ID = id.New("gnp")
		req.CreatedAt = time.Time{}
	} else {
		prior, ok := s.store.GroupPolicy(req.ID)
		if !ok {
			return groupPolicyView{}, fmt.Errorf("group policy %q not found", req.ID)
		}
		req.CreatedAt = prior.CreatedAt
	}
	if err := s.store.UpsertGroupPolicy(req); err != nil {
		return groupPolicyView{}, err
	}
	stored, _ := s.store.GroupPolicy(req.ID)
	action := "group.policy.update"
	if creating {
		action = "group.policy.create"
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   action,
		Scope:    "netpolicy:admin",
		Metadata: map[string]string{"group_policy_id": stored.ID, "scope_group_id": stored.ScopeGroupID},
	})
	return s.toGroupPolicyView(stored), nil
}

// validateGroupRule does a light structural check; full nft validation happens
// at plan time via netpolicy.NormalizePolicy on the EXPANDED per-node policy.
func (s *Server) validateGroupRule(r model.GroupNetRule) error {
	switch strings.ToLower(strings.TrimSpace(r.Action)) {
	case "allow", "deny":
	default:
		return fmt.Errorf("action must be allow or deny, got %q", r.Action)
	}
	switch strings.ToLower(strings.TrimSpace(r.Direction)) {
	case "egress", "ingress":
	default:
		return fmt.Errorf("direction must be egress or ingress, got %q", r.Direction)
	}
	switch r.Remote.Kind {
	case model.NetRefNode, model.NetRefCIDR, model.NetRefDomain, model.NetRefAny:
	case model.NetRefGroup:
		if _, ok := s.store.Group(strings.TrimSpace(r.Remote.GroupID)); !ok {
			return fmt.Errorf("remote group %q not found", r.Remote.GroupID)
		}
	default:
		return fmt.Errorf("invalid remote kind %q", r.Remote.Kind)
	}
	return nil
}

func (s *Server) handleDeleteGroupPolicy(w http.ResponseWriter, r *http.Request, p principal) {
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
	// Same reach rule as the upsert above: deleting a definition withdraws
	// policy from every node its group resolves to, so the caller must reach
	// them all. A policy id that does not resolve falls through to the store's
	// own not-found answer; group policies are listable under netpolicy:read,
	// so the id is not a secret this check could turn into an oracle.
	if gp, ok := s.store.GroupPolicy(req.ID); ok {
		if !s.requireGroupPolicyReach(w, p, "deleting this group policy", s.groupPolicyReach(gp.ScopeGroupID)) {
			return
		}
	}
	if err := s.store.DeleteGroupPolicy(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "group.policy.delete",
		Scope:    "netpolicy:admin",
		Metadata: map[string]string{"group_policy_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type groupPlanResult struct {
	NodeID     string `json:"node_id"`
	ApprovalID string `json:"approval_id"`
	PlanSHA    string `json:"plan_sha"`
}

type groupPlanConflict struct {
	NodeID string `json:"node_id"`
	Reason string `json:"reason"`
}

type groupPlanSelectorImpact struct {
	GroupID           string               `json:"group_id"`
	GroupName         string               `json:"group_name"`
	Uses              []string             `json:"uses"`
	PolicyIDs         []string             `json:"policy_ids"`
	Selector          *model.GroupSelector `json:"selector,omitempty"`
	ExplicitMemberIDs []string             `json:"explicit_member_ids"`
	SelectorMemberIDs []string             `json:"selector_member_ids"`
	ResolvedMemberIDs []string             `json:"resolved_member_ids"`
}

// handleGroupPolicyPlan materializes the EFFECTIVE per-node policy for every
// node covered by any enabled group policy, compiles each via the existing
// per-node compiler, and creates one Approval per node. It re-expands from
// CURRENT membership every call, so the plan SHA always reflects live
// membership (no staleness). It refuses to overwrite a manually-authored
// (non-group-derived) policy — those nodes are reported as conflicts, never
// silently clobbered. Nodes that previously had a group-derived policy but are
// now out of scope are reported as orphaned (left intact for explicit cleanup).
func (s *Server) handleGroupPolicyPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	opts, err := s.netPolicyCompileOptions()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodes := s.store.Nodes()
	groupList := s.store.Groups()
	groupPolicies := s.store.GroupPolicies()
	resolved := groups.ResolveAll(groupList, nodes)
	selectorImpacts := groupPolicySelectorImpacts(groupPolicies, groupList, resolved)
	effective := netpolicy.ExpandGroupPolicies(groupPolicies, resolved)

	// Authorization: the caller must hold netpolicy:admin on every affected node.
	targets := make([]string, 0, len(effective))
	for nodeID := range effective {
		targets = append(targets, nodeID)
	}
	sort.Strings(targets)
	if !s.requireAllNodeScopes(w, p, "netpolicy:admin", targets) {
		return
	}

	results := make([]groupPlanResult, 0, len(targets))
	conflicts := make([]groupPlanConflict, 0)
	approvalReason := ""
	if len(selectorImpacts) > 0 {
		approvalReason = "Planned from selector-backed group policy; selector membership is dynamic. Re-plan before approving if node tags, role, or geo changed."
	}
	for _, nodeID := range targets {
		eff := effective[nodeID]
		// Clobber-guard: never overwrite a manual (non-group-derived) policy.
		if existing, ok := s.store.NetPolicy(nodeID); ok && !existing.GroupDerived && len(existing.Rules) > 0 {
			conflicts = append(conflicts, groupPlanConflict{NodeID: nodeID, Reason: "node has a manually-authored network policy; resolve before applying group policy"})
			continue
		}
		// netpolicy:admin is held on every target above, but a group rule can
		// name a remote node that is not itself a target, and compiling one
		// embeds that node's WireGuard IP and public addresses into the plan
		// stored and returned here. Group expansion made this worse than the
		// single-node case: one plan call fans out across many targets, so one
		// unreadable remote leaks through every plan that names it.
		//
		// Refused rather than filtered, and refused per target rather than for
		// the whole batch: a target whose rules are all readable still gets a
		// correct plan, while a target that would need an unreadable remote
		// gets no plan at all instead of a ruleset missing rules.
		resolver := s.nodeResolverFor(p, "netpolicy:read", "planning this group policy", nodeID)
		normalized, err := netpolicy.NormalizePolicy(eff, resolver.Resolve)
		// Checked before err on purpose: the compiler names the node it could
		// not resolve, and that name is what the refusal exists to withhold.
		if refused := resolver.Refused(); refused != nil {
			conflicts = append(conflicts, groupPlanConflict{NodeID: nodeID, Reason: refused.Error()})
			continue
		}
		if err != nil {
			conflicts = append(conflicts, groupPlanConflict{NodeID: nodeID, Reason: "expansion failed validation: " + err.Error()})
			continue
		}
		normalized.GroupDerived = true
		egressPlan, err := netpolicy.CompileEgressPlan(normalized, resolver.Resolve, opts)
		if refused := resolver.Refused(); refused != nil {
			conflicts = append(conflicts, groupPlanConflict{NodeID: nodeID, Reason: refused.Error()})
			continue
		}
		if err != nil {
			conflicts = append(conflicts, groupPlanConflict{NodeID: nodeID, Reason: "compile failed: " + err.Error()})
			continue
		}
		plan := egressPlan.Ruleset
		sum := sha256.Sum256([]byte(plan))
		normalized.LastPlanSHA = hex.EncodeToString(sum[:])
		normalized.LastError = ""
		if err := s.store.UpsertNetPolicy(normalized); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		approval := model.Approval{
			ID:        id.New("approval"),
			NodeID:    nodeID,
			Plugin:    "nftpolicy",
			Action:    nftPolicyApprovalAction(s.publicURL, nftPolicyDomainSetBindings(egressPlan.DomainSets)...),
			Plan:      plan,
			Status:    model.ApprovalPending,
			Reason:    approvalReason,
			ActorID:   p.ActorID,
			CreatedAt: time.Now().UTC(),
		}
		approval, err = s.submitApproval(r.Context(), approval)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		results = append(results, groupPlanResult{NodeID: nodeID, ApprovalID: approval.ID, PlanSHA: normalized.LastPlanSHA})
	}

	// Orphans: group-derived policies whose node is no longer in scope.
	orphaned := make([]string, 0)
	for _, np := range s.store.NetPolicies() {
		if np.GroupDerived {
			if _, stillCovered := effective[np.TargetNodeID]; !stillCovered {
				orphaned = append(orphaned, np.TargetNodeID)
			}
		}
	}
	sort.Strings(orphaned)

	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		Action: "group.policy.plan",
		Scope:  "netpolicy:admin",
		Metadata: map[string]string{
			"affected":        fmt.Sprintf("%d", len(results)),
			"conflicts":       fmt.Sprintf("%d", len(conflicts)),
			"orphaned":        fmt.Sprintf("%d", len(orphaned)),
			"selector_groups": fmt.Sprintf("%d", len(selectorImpacts)),
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"affected":         results,
		"conflicts":        conflicts,
		"orphaned":         orphaned,
		"selector_impacts": selectorImpacts,
	})
}

func groupPolicySelectorImpacts(policies []model.GroupNetPolicy, groupList []model.Group, resolved map[string][]string) []groupPlanSelectorImpact {
	type usage struct {
		uses      map[string]struct{}
		policyIDs map[string]struct{}
	}

	used := make(map[string]*usage)
	mark := func(groupID, use, policyID string) {
		groupID = strings.TrimSpace(groupID)
		if groupID == "" {
			return
		}
		u := used[groupID]
		if u == nil {
			u = &usage{uses: map[string]struct{}{}, policyIDs: map[string]struct{}{}}
			used[groupID] = u
		}
		u.uses[use] = struct{}{}
		if policyID != "" {
			u.policyIDs[policyID] = struct{}{}
		}
	}

	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		mark(policy.ScopeGroupID, "scope", policy.ID)
		for _, rule := range policy.Rules {
			if rule.Disabled || rule.Remote.Kind != model.NetRefGroup {
				continue
			}
			mark(rule.Remote.GroupID, "remote", policy.ID)
		}
	}

	byID := make(map[string]model.Group, len(groupList))
	for _, g := range groupList {
		byID[g.ID] = g
	}

	out := make([]groupPlanSelectorImpact, 0, len(used))
	for groupID, u := range used {
		g, ok := byID[groupID]
		if !ok || g.Selector == nil {
			continue
		}
		explicit := sortedNonEmptyUnique(g.Members)
		explicitSet := make(map[string]struct{}, len(explicit))
		for _, id := range explicit {
			explicitSet[id] = struct{}{}
		}
		resolvedMembers := sortedNonEmptyUnique(resolved[groupID])
		selectorMembers := make([]string, 0)
		for _, id := range resolvedMembers {
			if _, explicit := explicitSet[id]; !explicit {
				selectorMembers = append(selectorMembers, id)
			}
		}
		out = append(out, groupPlanSelectorImpact{
			GroupID:           groupID,
			GroupName:         g.Name,
			Uses:              sortedSetKeys(u.uses),
			PolicyIDs:         sortedSetKeys(u.policyIDs),
			Selector:          g.Selector,
			ExplicitMemberIDs: explicit,
			SelectorMemberIDs: selectorMembers,
			ResolvedMemberIDs: resolvedMembers,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GroupName != out[j].GroupName {
			return out[i].GroupName < out[j].GroupName
		}
		return out[i].GroupID < out[j].GroupID
	})
	return out
}

func sortedSetKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		if strings.TrimSpace(key) != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func sortedNonEmptyUnique(in []string) []string {
	set := make(map[string]struct{}, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return sortedSetKeys(set)
}

// currentGroupDerivedPolicyPlanSHA recompiles a group-derived policy so the
// approve path can prove the stored plan still matches what the group model
// produces now. It deliberately resolves without a principal.
//
// The reasoning, because this is the one place that looks like the defect and
// is not: the recompile output is a hash compared in memory, never returned.
// The auto-approve policy engine drives this path under a synthetic identity
// that holds no scopes at all, so a scoped resolver would deny every remote and
// silently stop auto-approving group policy, which is a correctness break for a
// disclosure that does not happen. The error strings below are the only thing a
// caller sees, and they are written to name the target node the caller already
// asked about and nothing else.
func (s *Server) currentGroupDerivedPolicyPlanSHA(nodeID string) (string, error) {
	opts, err := s.netPolicyCompileOptions()
	if err != nil {
		return "", err
	}
	nodes := s.store.Nodes()
	resolved := groups.ResolveAll(s.store.Groups(), nodes)
	effective := netpolicy.ExpandGroupPolicies(s.store.GroupPolicies(), resolved)
	eff, ok := effective[nodeID]
	if !ok {
		return "", fmt.Errorf("group-derived netpolicy %q is no longer covered by any enabled group policy; re-plan before approving", nodeID)
	}
	resolver := s.systemNodeResolver("freshness hash only; never returned to the caller")
	normalized, err := netpolicy.NormalizePolicy(eff, resolver.Resolve)
	if err != nil {
		// The wrapped compiler error names the remote node it could not
		// resolve. An approver scoped to this target need not learn that name,
		// so the cause is dropped and only the target is reported.
		return "", fmt.Errorf("group-derived netpolicy %q no longer validates; re-plan before approving", nodeID)
	}
	plan, err := netpolicy.CompileEgressPlan(normalized, resolver.Resolve, opts)
	if err != nil {
		return "", fmt.Errorf("group-derived netpolicy %q no longer compiles; re-plan before approving", nodeID)
	}
	sum := sha256.Sum256([]byte(plan.Ruleset))
	return hex.EncodeToString(sum[:]), nil
}

// --- Reachability matrix (read-only) ---

type matrixCell struct {
	From      string   `json:"from"` // source group id
	To        string   `json:"to"`   // dest group id
	Action    string   `json:"action"`
	Protocols []string `json:"protocols,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	RuleCount int      `json:"rule_count"`
	Mixed     bool     `json:"mixed"` // allow and deny both present for this pair
}

type matrixGroup struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Slug  string `json:"slug"`
	Color string `json:"color"`
}

func (s *Server) handleNetPolicyMatrix(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	direction := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction")))
	if direction != "ingress" {
		direction = "egress"
	}
	gs := s.store.Groups()
	mgs := make([]matrixGroup, 0, len(gs))
	for _, g := range gs {
		mgs = append(mgs, matrixGroup{ID: g.ID, Name: g.Name, Slug: g.Slug, Color: g.Color})
	}

	type agg struct {
		actions   map[string]bool
		protocols map[string]bool
		ports     map[int]bool
		count     int
	}
	cells := map[string]*agg{} // key: from|to
	external := map[string]int{}
	for _, gp := range s.store.GroupPolicies() {
		if !gp.Enabled {
			continue
		}
		for _, rule := range gp.Rules {
			if rule.Disabled || strings.ToLower(rule.Direction) != direction {
				continue
			}
			if rule.Remote.Kind != model.NetRefGroup {
				external[gp.ScopeGroupID]++
				continue
			}
			key := gp.ScopeGroupID + "|" + rule.Remote.GroupID
			a := cells[key]
			if a == nil {
				a = &agg{actions: map[string]bool{}, protocols: map[string]bool{}, ports: map[int]bool{}}
				cells[key] = a
			}
			a.actions[strings.ToLower(rule.Action)] = true
			if rule.Protocol != "" {
				a.protocols[strings.ToLower(rule.Protocol)] = true
			}
			for _, port := range rule.Ports {
				a.ports[port] = true
			}
			a.count++
		}
	}

	out := make([]matrixCell, 0, len(cells))
	for key, a := range cells {
		parts := strings.SplitN(key, "|", 2)
		action := "allow"
		if a.actions["deny"] && !a.actions["allow"] {
			action = "deny"
		}
		cell := matrixCell{
			From:      parts[0],
			To:        parts[1],
			Action:    action,
			Protocols: sortedKeys(a.protocols),
			Ports:     sortedIntKeys(a.ports),
			RuleCount: a.count,
			Mixed:     a.actions["allow"] && a.actions["deny"],
		}
		out = append(out, cell)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	ext := make([]map[string]any, 0, len(external))
	for from, n := range external {
		ext = append(ext, map[string]any{"from": from, "rule_count": n})
	}
	sort.Slice(ext, func(i, j int) bool { return ext[i]["from"].(string) < ext[j]["from"].(string) })

	writeJSON(w, http.StatusOK, map[string]any{
		"direction": direction,
		"groups":    mgs,
		"cells":     out,
		"external":  ext,
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedIntKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
