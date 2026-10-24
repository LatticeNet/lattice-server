package server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Security groups bound to node groups (design 32 D3, S4). The binding is a
// global object: a node group can grow with no write to carry a reach check,
// so reading, writing and planning it need an unrestricted principal, and
// group:read because it names the group and its members. It never adopts a
// node; it reaches a managed member only through a NetGuard plan the
// operator approves, and the batch plan below is how a binding change, a
// member that joined or a member that left gets one.

const nodeGroupBindingInactive = "group binding inactive: node not managed"

type nodeGroupGuardMember struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name,omitempty"`
	// State is active (NetGuard manages the node and compiles the groups)
	// or inactive (the binding does nothing there until NetGuard adopts it).
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type nodeGroupGuardBindingView struct {
	model.NodeGroupGuardBinding
	GroupName string                 `json:"group_name"`
	Members   []nodeGroupGuardMember `json:"members"`
}

type nodeGroupChoice struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// requireNodeGroupGuardScope is the gate of every node-group binding route.
func (s *Server) requireNodeGroupGuardScope(w http.ResponseWriter, p principal, scope string) bool {
	return s.requireGlobalNetGuardScope(w, p, scope) && s.requireScope(w, p, "group:read")
}

func (s *Server) nodeGroupGuardBindingView(b model.NodeGroupGuardBinding, g model.Group, nodes []model.Node) nodeGroupGuardBindingView {
	view := nodeGroupGuardBindingView{NodeGroupGuardBinding: b, GroupName: g.Name, Members: []nodeGroupGuardMember{}}
	names := nodeNamesOf(nodes)
	for _, nodeID := range groups.ResolveMembers(g, nodes) {
		name, known := names[nodeID]
		if !known {
			continue
		}
		member := nodeGroupGuardMember{NodeID: nodeID, NodeName: name, State: "active"}
		if !s.nodeGuardManaged(nodeID) {
			member.State, member.Reason = "inactive", nodeGroupBindingInactive
		}
		view.Members = append(view.Members, member)
	}
	return view
}

// handleNetGuardNodeGroupBindings serves GET (every binding, and the node
// groups a binding may name) and POST (upsert one).
func (s *Server) handleNetGuardNodeGroupBindings(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireNodeGroupGuardScope(w, p, "netguard:read") {
			return
		}
		nodes := s.store.Nodes()
		byID := map[string]model.Group{}
		choices := []nodeGroupChoice{}
		for _, g := range s.store.Groups() {
			byID[g.ID] = g
			choices = append(choices, nodeGroupChoice{ID: g.ID, Name: g.Name, Members: groups.ResolveMembers(g, nodes)})
		}
		sort.Slice(choices, func(i, j int) bool {
			if choices[i].Name != choices[j].Name {
				return choices[i].Name < choices[j].Name
			}
			return choices[i].ID < choices[j].ID
		})
		views := []nodeGroupGuardBindingView{}
		for _, b := range s.store.NodeGroupGuardBindings() {
			views = append(views, s.nodeGroupGuardBindingView(b, byID[b.GroupID], nodes))
		}
		writeJSON(w, http.StatusOK, map[string]any{"bindings": views, "node_groups": choices})
	case http.MethodPost:
		s.upsertNodeGroupGuardBinding(w, r, p)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) upsertNodeGroupGuardBinding(w http.ResponseWriter, r *http.Request, p principal) {
	if !s.requireNodeGroupGuardScope(w, p, "netguard:admin") {
		return
	}
	var req model.NodeGroupGuardBinding
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.GroupID = strings.TrimSpace(req.GroupID)
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, fieldErrorf("group_id", "group_id is required"))
		return
	}
	g, ok := s.store.Group(req.GroupID)
	if !ok {
		writeError(w, http.StatusNotFound, fieldErrorf("group_id", "node group %q not found", req.GroupID))
		return
	}
	seen := map[string]bool{}
	for i, sgID := range req.SecurityGroupIDs {
		path := fieldIndex("security_group_ids", i)
		if seen[sgID] {
			writeError(w, http.StatusBadRequest, fieldErrorf(path, "security group %q is listed twice", sgID))
			return
		}
		seen[sgID] = true
		if strings.HasPrefix(sgID, netguard.LegacyGroupPrefix) {
			writeError(w, http.StatusBadRequest, fieldErrorf(path, "security group %q is one node's adopted baseline and binds only to that node", sgID))
			return
		}
		if _, ok := s.store.SecurityGroup(sgID); !ok {
			writeError(w, http.StatusBadRequest, fieldErrorf(path, "security group %q not found", sgID))
			return
		}
	}
	saved, err := s.store.UpsertNodeGroupGuardBinding(req)
	switch {
	case errors.Is(err, store.ErrGuardVersionConflict):
		writeError(w, http.StatusConflict, versionConflict(errors.New("the node group's security-group binding changed since it was read")))
		return
	case errors.Is(err, store.ErrGuardReferenceMissing):
		writeError(w, http.StatusBadRequest, err)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "netguard.node_group_binding.upsert", Scope: "netguard:admin",
		Metadata: map[string]string{"group_id": saved.GroupID, "security_group_ids": strings.Join(saved.SecurityGroupIDs, ",")},
	})
	writeJSON(w, http.StatusOK, s.nodeGroupGuardBindingView(saved, g, s.store.Nodes()))
}

func (s *Server) handleDeleteNetGuardNodeGroupBinding(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireNodeGroupGuardScope(w, p, "netguard:admin") {
		return
	}
	var req struct {
		GroupID string `json:"group_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	deleted, err := s.store.DeleteNodeGroupGuardBinding(strings.TrimSpace(req.GroupID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, errors.New("node group has no security-group binding"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "netguard.node_group_binding.delete", Scope: "netguard:admin",
		Metadata: map[string]string{"group_id": req.GroupID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// nodeGroupPlanGroup is one security group in a node's compile order.
type nodeGroupPlanGroup struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// ViaNodeGroup names the node group a derived group comes through.
	ViaNodeGroup *nodeNetworkRef `json:"via_node_group,omitempty"`
}

type nodeGroupPlanNode struct {
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	PlanSHA    string `json:"plan_sha,omitempty"`
	// Added and Removed are the derived groups this plan adds to and removes
	// from what the node's last apply compiled.
	Added   []nodeGroupPlanGroup `json:"added"`
	Removed []nodeGroupPlanGroup `json:"removed"`
	// Change says in a sentence what differs from the last apply.
	Change string `json:"change,omitempty"`
	// Order is the node's security groups in compile order, own first.
	Order    []nodeGroupPlanGroup `json:"order"`
	Findings []netguard.Finding   `json:"findings,omitempty"`
}

type nodeGroupPlanSkipped struct {
	NodeID       string             `json:"node_id"`
	NodeName     string             `json:"node_name,omitempty"`
	ViaNodeGroup *nodeNetworkRef    `json:"via_node_group,omitempty"`
	Reason       string             `json:"reason"`
	Findings     []netguard.Finding `json:"findings,omitempty"`
}

// handleNetGuardNodeGroupPlan is the batch plan of design 32 D3, shaped like
// handleGroupPolicyPlan: it plans every managed node whose derived security
// groups differ from what its last apply compiled, or that derives groups
// and whose compiled table differs from the last one applied, one approval
// per node, each named with what changes. With group_id it plans only the
// nodes that derive, or last applied, groups through that node group. Nodes
// in sync are listed as unchanged, unmanaged members as inactive, and a node
// whose plan cannot be made as a conflict with the reason.
func (s *Server) handleNetGuardNodeGroupPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		GroupID           string `json:"group_id,omitempty"`
		AcceptLockoutRisk bool   `json:"accept_lockout_risk"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if !s.requireNodeGroupGuardScope(w, p, "netguard:admin") || !s.requireScope(w, p, "network:plan") {
		return
	}
	if req.GroupID != "" {
		if _, ok := s.store.Group(req.GroupID); !ok {
			writeError(w, http.StatusNotFound, fieldErrorf("group_id", "node group %q not found", req.GroupID))
			return
		}
	}
	nodes := s.store.Nodes()
	names := nodeNamesOf(nodes)
	groupNames := groupNamesOf(s.store.Groups())
	sgName := func(sgID string) string {
		if sg, ok := s.store.SecurityGroup(sgID); ok {
			return sg.Name
		}
		return ""
	}
	planGroup := func(d model.DerivedSecurityGroup) nodeGroupPlanGroup {
		return nodeGroupPlanGroup{ID: d.SecurityGroupID, Name: sgName(d.SecurityGroupID),
			ViaNodeGroup: &nodeNetworkRef{ID: d.NodeGroupID, Name: groupNames[d.NodeGroupID]}}
	}
	reaches := func(derived []model.DerivedSecurityGroup) bool {
		for _, d := range derived {
			if req.GroupID == "" || d.NodeGroupID == req.GroupID {
				return true
			}
		}
		return false
	}

	affected := []nodeGroupPlanNode{}
	// plans[i] is affected[i]'s anchor and approval, written together below.
	plans := []store.GuardPlan{}
	unchanged := []nodeGroupPlanSkipped{}
	conflicts := []nodeGroupPlanSkipped{}
	inactive := []nodeGroupPlanSkipped{}
	lockoutAccepted := 0
	for _, binding := range s.store.NodeGuardBindings() {
		if !binding.Managed {
			continue
		}
		nodeID := binding.NodeID
		conflict := func(reason string, findings []netguard.Finding) {
			conflicts = append(conflicts, nodeGroupPlanSkipped{NodeID: nodeID, NodeName: names[nodeID], Reason: reason, Findings: findings})
		}
		input, snapshot, resolver, err := s.compileInputSnapshotFor(p, nodeID)
		if err != nil {
			conflict("its NetGuard intent cannot be read: "+err.Error(), nil)
			continue
		}
		derivedNow := derivedSecurityGroupsOf(snapshot.Derived)
		if !reaches(derivedNow) && !reaches(binding.AppliedDerived) {
			continue
		}
		compiled, err := netguard.Compile(input)
		// Before err: the compiler names the node it could not resolve.
		if refused := resolver.Refused(); refused != nil {
			conflict(refused.Error(), nil)
			continue
		}
		if err != nil {
			conflict("compile failed: "+err.Error(), nil)
			continue
		}
		ruleset, err := network.GenerateNFTPlan(compiled)
		if err != nil {
			conflict("render failed: "+err.Error(), nil)
			continue
		}
		added, removed := derivedDiff(binding.AppliedDerived, derivedNow)
		lastRuleset, hasLast := s.lastAppliedGuardRuleset(nodeID)
		rulesChanged := !hasLast || rulesetDigest(ruleset) != rulesetDigest(lastRuleset)
		if len(added) == 0 && len(removed) == 0 && !rulesChanged {
			unchanged = append(unchanged, nodeGroupPlanSkipped{NodeID: nodeID, NodeName: names[nodeID], Reason: "matches its last apply"})
			continue
		}
		if dns := s.dnsListenerFindings(nodeID, compiled, input.Zones); len(dns) > 0 {
			conflict(dnsListenerRefusal(dns).Error(), dns)
			continue
		}
		findings := netguard.Lint(compiled, netguard.LintOptions{
			PublicURLConfigured: s.publicURL != "",
			Reality:             s.guardRealityForLint(nodeID),
		})
		if netguard.Blocking(findings) && !req.AcceptLockoutRisk {
			conflict("plan blocked by lint findings", findings)
			continue
		}
		approval := model.Approval{
			ID:        id.New("approval"),
			NodeID:    nodeID,
			Plugin:    "nft",
			Action:    netGuardApprovalAction,
			Plan:      ruleset,
			Status:    model.ApprovalPending,
			Reason:    "Planned from node-group security-group bindings; membership is dynamic. Re-plan before approving if the node's groups changed.",
			ActorID:   p.ActorID,
			CreatedAt: time.Now().UTC(),
		}
		planned := input.Binding
		planned.LastPlanSHA = approvalPlanSHA(approval)
		planned.LastError = ""
		node := nodeGroupPlanNode{NodeID: nodeID, NodeName: names[nodeID], ApprovalID: approval.ID, PlanSHA: planned.LastPlanSHA,
			Added: []nodeGroupPlanGroup{}, Removed: []nodeGroupPlanGroup{}, Order: []nodeGroupPlanGroup{}, Findings: findings}
		for _, d := range added {
			node.Added = append(node.Added, planGroup(d))
		}
		for _, d := range removed {
			node.Removed = append(node.Removed, planGroup(d))
		}
		node.Change = derivedChangeSentence(node.Added, node.Removed, rulesChanged)
		for _, sgID := range input.Binding.GroupIDs {
			node.Order = append(node.Order, nodeGroupPlanGroup{ID: sgID, Name: sgName(sgID)})
		}
		for _, d := range derivedNow {
			node.Order = append(node.Order, planGroup(d))
		}
		plans = append(plans, store.GuardPlan{Binding: planned, Approval: approval})
		affected = append(affected, node)
		if s.nodeGroupPlanHook != nil {
			s.nodeGroupPlanHook(nodeID)
		}
	}

	// The batch is written in one commit, every anchor and approval or none,
	// so a failure on one node never leaves the others' plans behind.
	if len(plans) > 0 {
		stored, committed, err := s.store.CommitGuardPlans(plans)
		if !committed {
			var moved *store.GuardPlanConflictError
			if errors.As(err, &moved) {
				label := moved.NodeID
				if name := names[moved.NodeID]; name != "" {
					label = fmt.Sprintf("%q (%s)", name, moved.NodeID)
				}
				writeError(w, http.StatusConflict, versionConflict(fmt.Errorf(
					"node %s: its NetGuard binding changed while the batch was planned, so no plan in the batch was written; plan again", label)))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if err != nil {
			// The whole batch is in; answering an error would invite a retry
			// that plans every node again.
			s.logger.Printf("netguard node-group plan committed with degraded durability: %v", err)
		}
		for i, approval := range stored {
			approval = s.evaluateApprovalAutoRules(r.Context(), approval)
			affected[i].ApprovalID = approval.ID
			if netguard.Blocking(affected[i].Findings) {
				lockoutAccepted++
				s.recordPrincipalAudit(p, model.AuditEvent{
					ID: id.New("audit"), NodeID: approval.NodeID, Action: "netguard.lockout_risk.accepted", Scope: "netguard:admin",
					Metadata: map[string]string{"node_id": approval.NodeID, "approval_id": approval.ID},
				})
			}
		}
	}

	// Unmanaged members: the binding is inactive there, and nothing is
	// planned or adopted.
	for _, b := range s.store.NodeGroupGuardBindings() {
		if len(b.SecurityGroupIDs) == 0 || (req.GroupID != "" && b.GroupID != req.GroupID) {
			continue
		}
		g, ok := s.store.Group(b.GroupID)
		if !ok {
			continue
		}
		for _, nodeID := range groups.ResolveMembers(g, nodes) {
			if _, known := names[nodeID]; !known || s.nodeGuardManaged(nodeID) {
				continue
			}
			inactive = append(inactive, nodeGroupPlanSkipped{NodeID: nodeID, NodeName: names[nodeID],
				ViaNodeGroup: &nodeNetworkRef{ID: g.ID, Name: g.Name}, Reason: nodeGroupBindingInactive})
		}
	}

	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "netguard.node_group.plan", Scope: "network:plan",
		Metadata: map[string]string{
			"group_id":              req.GroupID,
			"affected":              fmt.Sprintf("%d", len(affected)),
			"unchanged":             fmt.Sprintf("%d", len(unchanged)),
			"conflicts":             fmt.Sprintf("%d", len(conflicts)),
			"inactive":              fmt.Sprintf("%d", len(inactive)),
			"lockout_risk_accepted": fmt.Sprintf("%d", lockoutAccepted),
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"affected":  affected,
		"unchanged": unchanged,
		"conflicts": conflicts,
		"inactive":  inactive,
	})
}

func derivedSecurityGroupsOf(derived []store.DerivedGuardGroup) []model.DerivedSecurityGroup {
	out := make([]model.DerivedSecurityGroup, 0, len(derived))
	for _, d := range derived {
		out = append(out, d.DerivedSecurityGroup)
	}
	return out
}

// derivedDiff is what now adds to and removes from applied, compared as
// (security group, node group) pairs; order is now's and applied's.
func derivedDiff(applied, now []model.DerivedSecurityGroup) (added, removed []model.DerivedSecurityGroup) {
	for _, d := range now {
		if !slices.Contains(applied, d) {
			added = append(added, d)
		}
	}
	for _, d := range applied {
		if !slices.Contains(now, d) {
			removed = append(removed, d)
		}
	}
	return added, removed
}

func derivedChangeSentence(added, removed []nodeGroupPlanGroup, rulesChanged bool) string {
	describe := func(list []nodeGroupPlanGroup) string {
		parts := make([]string, 0, len(list))
		for _, g := range list {
			name := g.Name
			if name == "" {
				name = g.ID
			}
			via := g.ViaNodeGroup.Name
			if via == "" {
				via = g.ViaNodeGroup.ID
			}
			parts = append(parts, fmt.Sprintf("%s (via node group %s)", name, via))
		}
		return strings.Join(parts, ", ")
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "adds "+describe(added))
	}
	if len(removed) > 0 {
		parts = append(parts, "removes "+describe(removed))
	}
	if len(parts) == 0 && rulesChanged {
		return "its derived groups are unchanged, but its compiled table differs from the last one applied"
	}
	return strings.Join(parts, "; ")
}

// lastAppliedGuardRuleset is the ruleset the newest apply that reached the
// node wrote to lattice_guard, whoever wrote it (the test D4's re-plan
// pending uses).
func (s *Server) lastAppliedGuardRuleset(nodeID string) (string, bool) {
	for _, a := range s.store.NodeAppliedApprovals(nodeID, "nft", "selfdns", model.BeaconApprovalPlugin) {
		if _, ruleset, _, ok := guardWriteOf(a.Approval); ok {
			return ruleset, true
		}
	}
	return "", false
}
