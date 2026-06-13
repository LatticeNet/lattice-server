package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netpolicy"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

type netPolicyView struct {
	ID             string          `json:"id"`
	TargetNodeID   string          `json:"target_node_id"`
	TargetNodeName string          `json:"target_node_name,omitempty"`
	Rules          []model.NetRule `json:"rules"`
	Enabled        bool            `json:"enabled"`
	LastPlanSHA    string          `json:"last_plan_sha,omitempty"`
	LastAppliedAt  time.Time       `json:"last_applied_at,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (s *Server) handleNetPolicy(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		policies := s.store.NetPolicies()
		views := make([]netPolicyView, 0, len(policies))
		for _, policy := range policies {
			if rbac.Allows(p.Principal, "netpolicy:read", policy.TargetNodeID) {
				views = append(views, s.toNetPolicyView(policy))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": views})
	case http.MethodPost:
		var req model.NetPolicy
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if req.TargetNodeID == "" {
			writeError(w, http.StatusBadRequest, errors.New("target_node_id is required"))
			return
		}
		if !s.requireNodeScope(w, p, "netpolicy:admin", req.TargetNodeID) {
			return
		}
		policy, err := netpolicy.NormalizePolicy(req, s.resolveNode)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if existing, ok := s.store.NetPolicy(policy.TargetNodeID); ok {
			policy.CreatedAt = existing.CreatedAt
			policy.LastPlanSHA = existing.LastPlanSHA
			policy.LastAppliedAt = existing.LastAppliedAt
			policy.LastError = existing.LastError
		}
		if err := s.store.UpsertNetPolicy(policy); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if stored, ok := s.store.NetPolicy(policy.TargetNodeID); ok {
			policy = stored
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   policy.TargetNodeID,
			Action:   "network.policy.upsert",
			Scope:    "netpolicy:admin",
			Metadata: map[string]string{"target_node_id": policy.TargetNodeID},
		})
		writeJSON(w, http.StatusOK, s.toNetPolicyView(policy))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteNetPolicy(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		TargetNodeID string `json:"target_node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.TargetNodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("target_node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "netpolicy:admin", req.TargetNodeID) {
		return
	}
	if err := s.store.DeleteNetPolicy(req.TargetNodeID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   req.TargetNodeID,
		Action:   "network.policy.delete",
		Scope:    "netpolicy:admin",
		Metadata: map[string]string{"target_node_id": req.TargetNodeID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNetPolicyGraph(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodes := s.store.Nodes()
	visibleNodes := make([]model.Node, 0, len(nodes))
	for _, node := range nodes {
		if rbac.Allows(p.Principal, "netpolicy:read", node.ID) {
			visibleNodes = append(visibleNodes, node)
		}
	}
	policies := s.store.NetPolicies()
	visiblePolicies := make([]model.NetPolicy, 0, len(policies))
	for _, policy := range policies {
		if rbac.Allows(p.Principal, "netpolicy:read", policy.TargetNodeID) {
			visiblePolicies = append(visiblePolicies, policy)
		}
	}
	writeJSON(w, http.StatusOK, netpolicy.BuildGraph(visibleNodes, visiblePolicies))
}

func (s *Server) resolveNode(nodeID string) (model.Node, bool) {
	return s.store.Node(nodeID)
}

func (s *Server) toNetPolicyView(policy model.NetPolicy) netPolicyView {
	nodeName := ""
	if node, ok := s.store.Node(policy.TargetNodeID); ok {
		nodeName = node.Name
	}
	return netPolicyView{
		ID:             policy.ID,
		TargetNodeID:   policy.TargetNodeID,
		TargetNodeName: nodeName,
		Rules:          append([]model.NetRule(nil), policy.Rules...),
		Enabled:        policy.Enabled,
		LastPlanSHA:    policy.LastPlanSHA,
		LastAppliedAt:  policy.LastAppliedAt,
		LastError:      policy.LastError,
		UpdatedAt:      policy.UpdatedAt,
	}
}
