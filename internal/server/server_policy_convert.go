package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netpolicy"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// --- Converting a manual policy (design 32 D3) ---

// handleNetPolicyConvert turns a node's manually authored NetPolicy into the
// equivalent selector-scoped outbound policy, targeting that one node and
// keeping every rule in order, and retires the manual document in the same
// store write. An enabled policy also yields one reviewed plan: the node's
// new effective policy (the converted rules merged by priority with any other
// policy that reaches the node, which a manual policy used to block) is
// compiled and submitted for approval like any group plan. Nothing is stored
// when that plan cannot be produced, so a conversion is one reviewed plan or
// nothing. A disabled policy converts into a disabled one with no plan.
func (s *Server) handleNetPolicyConvert(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		TargetNodeID string `json:"target_node_id"`
		Name         string `json:"name"`
		Priority     int    `json:"priority"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	nodeID := strings.TrimSpace(req.TargetNodeID)
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("target_node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "netpolicy:admin", nodeID) {
		return
	}
	manual, ok := s.store.NetPolicy(nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("node %q has no outbound policy to convert", nodeID))
		return
	}
	if manual.GroupDerived {
		writeError(w, http.StatusConflict, fmt.Errorf("the policy on node %q is already built from outbound policies; edit those instead", nodeID))
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > maxOutboundPolicyNameLen {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name is longer than %d bytes", maxOutboundPolicyNameLen))
		return
	}
	rules := make([]model.GroupNetRule, 0, len(manual.Rules))
	for _, rule := range manual.Rules {
		rules = append(rules, model.GroupNetRule{
			ID:        rule.ID,
			Comment:   rule.Comment,
			Action:    rule.Action,
			Direction: rule.Direction,
			Protocol:  rule.Protocol,
			Ports:     append([]int(nil), rule.Ports...),
			Remote:    rule.Remote,
			Disabled:  rule.Disabled,
		})
	}
	scope := model.TargetSelector{Nodes: []string{nodeID}}
	gp := model.GroupNetPolicy{
		ID:       id.New("gnp"),
		Name:     name,
		Scope:    &scope,
		Rules:    rules,
		Enabled:  manual.Enabled,
		Priority: req.Priority,
	}
	if !s.authorizeOutboundPolicyWrite(w, p, "this outbound policy", scope, rules, nil) {
		return
	}
	for i, rule := range rules {
		if err := s.validateGroupRule(rule); err != nil {
			writeError(w, http.StatusConflict, fmt.Errorf("rule %d cannot be converted: %w", i+1, err))
			return
		}
	}

	var derived *model.NetPolicy
	var egressPlan netpolicy.EgressPlan
	merged := 0
	if gp.Enabled {
		opts, err := s.netPolicyCompileOptions()
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		nodes, groupList := s.store.Nodes(), s.store.Groups()
		policies := append(s.store.GroupPolicies(), gp)
		targets := netpolicy.PolicyTargets(policies, nodes, groupList)
		effective := netpolicy.ExpandGroupPolicies(policies, targets, groups.ResolveAll(groupList, nodes))
		eff, ok := effective[nodeID]
		if !ok {
			writeError(w, http.StatusConflict, fmt.Errorf("the policy on node %q has no enabled rule, so the converted policy would not plan; enable a rule or delete the policy", nodeID))
			return
		}
		for _, other := range policies {
			if other.ID == gp.ID || !other.Enabled {
				continue
			}
			for _, target := range targets[other.ID] {
				if target == nodeID {
					merged++
				}
			}
		}
		// Planned with the caller's own reach, as every plan is: a remote the
		// caller cannot read is refused, not filtered.
		resolver := s.nodeResolverFor(p, "netpolicy:read", "converting this policy", nodeID)
		normalized, err := netpolicy.NormalizePolicy(eff, resolver.Resolve)
		if s.writeRefusal(w, p, resolver) {
			return
		}
		if err != nil {
			writeError(w, http.StatusConflict, fmt.Errorf("nothing was converted: the converted policy does not validate: %w", err))
			return
		}
		normalized.GroupDerived = true
		egressPlan, err = netpolicy.CompileEgressPlan(normalized, resolver.Resolve, opts)
		if s.writeRefusal(w, p, resolver) {
			return
		}
		if err != nil {
			writeError(w, http.StatusConflict, fmt.Errorf("nothing was converted: the converted policy does not compile: %w", err))
			return
		}
		sum := sha256.Sum256([]byte(egressPlan.Ruleset))
		normalized.LastPlanSHA = hex.EncodeToString(sum[:])
		normalized.LastError = ""
		normalized.LastAppliedAt = manual.LastAppliedAt
		normalized.CreatedAt = manual.CreatedAt
		derived = &normalized
	}

	// The reviewed plan is submitted before the store write, so a conversion
	// is never stored without its plan: if the approval cannot be created,
	// nothing changed (Go review of S3a). If the write then loses a race with
	// another change to the node's document, the approval stays pending and
	// meets the approve-time freshness check like any plan
	// (requireCurrentNetPolicyApproval), which refuses it unless its ruleset
	// is still what the node's document compiles to.
	var approvalOut *approvalView
	approvalID := ""
	if derived != nil {
		reason := "Converted the manual outbound policy on this node into an outbound policy targeting it; the rules are unchanged."
		if merged > 0 {
			reason = fmt.Sprintf("Converted the manual outbound policy on this node into an outbound policy targeting it. %d other outbound policies also reach this node and now merge into it by priority; review the merged rules.", merged)
		}
		approval := model.Approval{
			ID:        id.New("approval"),
			NodeID:    nodeID,
			Plugin:    "nftpolicy",
			Action:    nftPolicyApprovalAction(s.publicURL, nftPolicyDomainSetBindings(egressPlan.DomainSets)...),
			Plan:      egressPlan.Ruleset,
			Status:    model.ApprovalPending,
			Reason:    reason,
			ActorID:   p.ActorID,
			CreatedAt: time.Now().UTC(),
		}
		approval, err := s.submitApproval(r.Context(), approval)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		view := toApprovalView(approval)
		approvalOut = &view
		approvalID = approval.ID
	}

	if err := s.store.ConvertNetPolicy(nodeID, gp, derived); err != nil {
		if errors.Is(err, store.ErrNetPolicyNotManual) {
			writeError(w, http.StatusConflict, fmt.Errorf("the policy on node %q changed while converting, so nothing was converted; reload and try again", nodeID))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	stored, _ := s.store.GroupPolicy(gp.ID)

	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: nodeID,
		Action: "network.policy.convert",
		Scope:  "netpolicy:admin",
		Metadata: map[string]string{
			"target_node_id":  nodeID,
			"group_policy_id": stored.ID,
			"rules":           fmt.Sprintf("%d", len(stored.Rules)),
			"approval_id":     approvalID,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"group_policy": s.toGroupPolicyView(p, stored, s.store.Nodes(), s.store.Groups()),
		"approval":     approvalOut,
	})
}
