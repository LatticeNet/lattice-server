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
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Outbound policy (iter-063 group policy, design 32 D3 targets). Operators
// author intent once per target; the target is a selector naming nodes, node
// groups or the whole fleet. The server EXPANDS it into per-node
// model.NetPolicy documents that feed the unchanged per-node
// compile/approval/apply path. The agent never sees a group ref.

type groupPolicyView struct {
	model.GroupNetPolicy
	ScopeGroupName string `json:"scope_group_name,omitempty"`
	GroupRuleCount int    `json:"group_rule_count"`
	// Target is the effective selector: the stored scope, or the one-group
	// selector a stored scope_group_id stands for. Reading never rewrites the
	// stored document.
	Target model.TargetSelector `json:"target"`
	// TargetNodeIDs is Target resolved against the fleet now, limited to the
	// nodes the caller may read under netpolicy:read, the same subset the
	// group preview answers from.
	TargetNodeIDs []string `json:"target_node_ids"`
	// Label names the policy where it is listed: its name, or its target.
	Label string `json:"label"`
}

func (s *Server) toGroupPolicyView(p principal, gp model.GroupNetPolicy, nodes []model.Node, groupList []model.Group) groupPolicyView {
	name := ""
	if g, ok := s.store.Group(gp.ScopeGroupID); ok {
		name = g.Name
	}
	target := gp.TargetScope()
	readable := make([]string, 0)
	for _, nodeID := range groups.ResolveTargets(target, nodes, groupList) {
		if rbac.Allows(p.Principal, "netpolicy:read", nodeID) {
			readable = append(readable, nodeID)
		}
	}
	return groupPolicyView{
		GroupNetPolicy: gp,
		ScopeGroupName: name,
		GroupRuleCount: len(gp.Rules),
		Target:         target,
		TargetNodeIDs:  readable,
		Label:          outboundPolicyLabel(gp, groupNamesOf(groupList)),
	}
}

func groupNamesOf(groupList []model.Group) map[string]string {
	out := make(map[string]string, len(groupList))
	for _, g := range groupList {
		out[g.ID] = g.Name
	}
	return out
}

// outboundPolicyLabel names a policy: its name, or "targeting" and a short
// description of its target. Nodes appear by id, the form every policy view
// already carries in its scope and rules, and groups by name.
func outboundPolicyLabel(gp model.GroupNetPolicy, groupNames map[string]string) string {
	if name := strings.TrimSpace(gp.Name); name != "" {
		return name
	}
	return "targeting " + describeTargetSelector(gp.TargetScope(), groupNames)
}

func describeTargetSelector(sel model.TargetSelector, groupNames map[string]string) string {
	if sel.All {
		if len(sel.Exclude) == 0 {
			return "the whole fleet"
		}
		return "the whole fleet except " + shortList(sel.Exclude)
	}
	names := make([]string, 0, len(sel.Groups)+len(sel.Nodes))
	for _, gid := range sel.Groups {
		if name := groupNames[gid]; name != "" {
			names = append(names, name)
		} else {
			names = append(names, gid)
		}
	}
	names = append(names, sel.Nodes...)
	if len(names) == 0 {
		return "nothing"
	}
	out := shortList(names)
	if len(sel.Exclude) > 0 {
		out += " except " + shortList(sel.Exclude)
	}
	return out
}

func shortList(items []string) string {
	const shown = 3
	if len(items) <= shown {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:shown], ", "), len(items)-shown)
}

func (s *Server) handleGroupPolicy(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "netpolicy:read") {
			return
		}
		policies := s.store.GroupPolicies()
		nodes, groupList := s.store.Nodes(), s.store.Groups()
		views := make([]groupPolicyView, 0, len(policies))
		for _, gp := range policies {
			views = append(views, s.toGroupPolicyView(p, gp, nodes, groupList))
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
		scope, err := normalizePolicyScope(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// The write is authorized against the policy being OVERWRITTEN as well
		// as the one being written, or a confined caller could name an existing
		// policy and narrow or re-point it, withdrawing policy from nodes it
		// cannot reach without ever being refused (security review,
		// 2026-09-07). An id that resolves to nothing falls through to
		// upsertGroupPolicy's own not-found answer rather than becoming a
		// second existence probe with different wording.
		var prior *model.GroupNetPolicy
		if priorID := strings.TrimSpace(req.ID); priorID != "" {
			if gp, ok := s.store.GroupPolicy(priorID); ok {
				prior = &gp
			}
		}
		if !s.authorizeOutboundPolicyWrite(w, p, "this outbound policy", scope, req.Rules, prior) {
			return
		}
		view, err := s.upsertGroupPolicy(req, scope, p)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// normalizePolicyScope returns the target selector a policy write stores:
// the request's scope with every id trimmed, deduplicated and sorted, or the
// one-group selector when the request names only scope_group_id (the older
// form, which stays an alias). It refuses the shapes that cannot mean what
// they say. Existence of the ids is checked later, after authorization, so a
// confined caller cannot use this as an existence probe.
func normalizePolicyScope(req model.GroupNetPolicy) (model.TargetSelector, error) {
	alias := strings.TrimSpace(req.ScopeGroupID)
	var sel model.TargetSelector
	switch {
	case req.Scope != nil:
		sel = model.TargetSelector{
			Nodes:   sortedNonEmptyUnique(req.Scope.Nodes),
			Groups:  sortedNonEmptyUnique(req.Scope.Groups),
			All:     req.Scope.All,
			Exclude: sortedNonEmptyUnique(req.Scope.Exclude),
		}
		if alias != "" && store.ScopeGroupAlias(sel) != alias {
			return model.TargetSelector{}, fmt.Errorf("scope_group_id %q disagrees with scope; send the scope alone", alias)
		}
	case alias != "":
		sel = model.TargetSelector{Groups: []string{alias}}
	}
	if sel.All && (len(sel.Nodes) > 0 || len(sel.Groups) > 0) {
		return model.TargetSelector{}, errors.New("a whole-fleet target names no nodes or node groups; use exclude to leave nodes out")
	}
	if !sel.All && len(sel.Nodes) == 0 && len(sel.Groups) == 0 {
		return model.TargetSelector{}, errors.New("an outbound policy needs a target: nodes, node groups or the whole fleet")
	}
	if len(sel.Exclude) > 0 && !sel.All && len(sel.Groups) == 0 {
		return model.TargetSelector{}, errors.New("exclude leaves nodes out of a node group or the whole fleet; with explicit nodes, list only the nodes to target")
	}
	excluded := make(map[string]struct{}, len(sel.Exclude))
	for _, nodeID := range sel.Exclude {
		excluded[nodeID] = struct{}{}
	}
	for _, nodeID := range sel.Nodes {
		if _, ok := excluded[nodeID]; ok {
			return model.TargetSelector{}, fmt.Errorf("node %q is both a target and excluded", nodeID)
		}
	}
	return sel, nil
}

// authorizeOutboundPolicyWrite applies the scope rule to a write of an
// outbound policy (design 32 D1's rule for stored selectors, applied to
// policy targets). An unrestricted principal passes. A node-restricted one may
// target only explicit nodes it holds netpolicy:admin on: a node group or the
// whole fleet is refused, because a stored selector is expanded at plan time
// by whoever plans, and the fleet-wide plan an unrestricted operator runs
// would apply a confined author's definition to every node the group resolves
// to then, including nodes the author cannot read; a selector-backed group
// grows on a tag or geo change with no write that could carry a check. The
// same holds for a rule's remote: a remote group is refused and a remote node
// must be readable, because compiling either embeds addresses into a plan the
// author may read back. The policy being overwritten or deleted (prior) must
// pass the same rule, so a confined caller cannot narrow or withdraw a group
// or fleet policy either.
func (s *Server) authorizeOutboundPolicyWrite(w http.ResponseWriter, p principal, what string, scope model.TargetSelector, rules []model.GroupNetRule, prior *model.GroupNetPolicy) bool {
	if !principalHasNodeRestriction(p) {
		return true
	}
	deny := func(reason, message string) bool {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   "authorize.nodeset",
			Scope:    "netpolicy:admin",
			Decision: "deny",
			Reason:   reason,
		})
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, message))
		return false
	}
	if len(scope.Groups) > 0 || scope.All {
		return deny("node-restricted token named a node group or the whole fleet as a policy target",
			what+" targets a node group or the whole fleet, which a token carrying a server allowlist cannot do; name the nodes instead")
	}
	ids := append(append([]string(nil), scope.Nodes...), scope.Exclude...)
	if prior != nil {
		priorScope := prior.TargetScope()
		if len(priorScope.Groups) > 0 || priorScope.All {
			return deny("node-restricted token tried to change a group or fleet policy",
				what+" currently targets a node group or the whole fleet, which a token carrying a server allowlist cannot change")
		}
		ids = append(append(ids, priorScope.Nodes...), priorScope.Exclude...)
	}
	if len(ids) == 0 {
		// Unreachable after normalizePolicyScope, kept so an empty set can
		// never pass requireReadableNodes vacuously.
		return deny("node-restricted token wrote a policy with no explicit node", what+" names no node")
	}
	if !s.requireReadableNodes(w, p, "netpolicy:admin", what, ids) {
		return false
	}
	remotes := make([]string, 0)
	for _, rule := range rules {
		switch rule.Remote.Kind {
		case model.NetRefGroup:
			return deny("node-restricted token named a node group as a policy remote",
				what+" names a node group as a remote, which a token carrying a server allowlist cannot do; name the nodes instead")
		case model.NetRefNode:
			remotes = append(remotes, rule.Remote.NodeID)
		}
	}
	return s.requireReadableNodes(w, p, "netpolicy:read", "a remote of "+what, remotes)
}

func (s *Server) upsertGroupPolicy(req model.GroupNetPolicy, scope model.TargetSelector, p principal) (groupPolicyView, error) {
	for _, nodeID := range append(append([]string(nil), scope.Nodes...), scope.Exclude...) {
		if _, ok := s.store.Node(nodeID); !ok {
			return groupPolicyView{}, fmt.Errorf("node %q not found", nodeID)
		}
	}
	for _, groupID := range scope.Groups {
		if _, ok := s.store.Group(groupID); !ok {
			return groupPolicyView{}, fmt.Errorf("node group %q not found", groupID)
		}
	}
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) > maxOutboundPolicyNameLen {
		return groupPolicyView{}, fmt.Errorf("name is longer than %d bytes", maxOutboundPolicyNameLen)
	}
	req.Scope = &scope
	req.ScopeGroupID = store.ScopeGroupAlias(scope)
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
	groupList := s.store.Groups()
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		Action: action,
		Scope:  "netpolicy:admin",
		Metadata: map[string]string{
			"group_policy_id": stored.ID,
			"scope_group_id":  stored.ScopeGroupID,
			"target":          describeTargetSelector(stored.TargetScope(), groupNamesOf(groupList)),
		},
	})
	return s.toGroupPolicyView(p, stored, s.store.Nodes(), groupList), nil
}

// maxOutboundPolicyNameLen bounds a policy name; it is a label, not a document.
const maxOutboundPolicyNameLen = 120

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
	// Same rule as the upsert: deleting a definition withdraws policy from
	// every node it targets, so a confined caller may delete only a policy
	// whose stored target is explicit nodes it administers. A policy id that
	// does not resolve falls through to the store's own not-found answer;
	// policies are listable under netpolicy:read, so the id is not a secret
	// this check could turn into an oracle.
	if gp, ok := s.store.GroupPolicy(req.ID); ok {
		if !s.authorizeOutboundPolicyWrite(w, p, "deleting this outbound policy", gp.TargetScope(), nil, &gp) {
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
	effective := netpolicy.ExpandGroupPolicies(groupPolicies, netpolicy.PolicyTargets(groupPolicies, nodes, groupList), resolved)

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
		for _, groupID := range policy.TargetScope().Groups {
			mark(groupID, "scope", policy.ID)
		}
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
	nodes, groupList, policies := s.store.Nodes(), s.store.Groups(), s.store.GroupPolicies()
	effective := netpolicy.ExpandGroupPolicies(policies, netpolicy.PolicyTargets(policies, nodes, groupList), groups.ResolveAll(groupList, nodes))
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
	// The matrix is the group-pair view of outbound policy: a row is a node
	// group a policy targets. A policy that targets only nodes or the whole
	// fleet has no group row and is read on the policy page instead.
	for _, gp := range s.store.GroupPolicies() {
		if !gp.Enabled {
			continue
		}
		for _, from := range gp.TargetScope().Groups {
			for _, rule := range gp.Rules {
				if rule.Disabled || strings.ToLower(rule.Direction) != direction {
					continue
				}
				if rule.Remote.Kind != model.NetRefGroup {
					external[from]++
					continue
				}
				key := from + "|" + rule.Remote.GroupID
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
