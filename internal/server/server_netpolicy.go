package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netpolicy"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

var controlPlaneHostRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

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
			if sameNetPolicyIntent(existing, policy) {
				policy.LastPlanSHA = existing.LastPlanSHA
				policy.LastAppliedAt = existing.LastAppliedAt
				policy.LastError = existing.LastError
			} else {
				policy.LastError = "policy changed since last plan; create a new plan before applying"
			}
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

func (s *Server) handleNetPolicyPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID       string `json:"node_id"`
		TargetNodeID string `json:"target_node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	nodeID := req.NodeID
	if nodeID == "" {
		nodeID = req.TargetNodeID
	}
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "netpolicy:admin", nodeID) {
		return
	}
	policy, ok := s.store.NetPolicy(nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("netpolicy not found"))
		return
	}
	opts, err := s.netPolicyCompileOptions()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plan, err := netpolicy.CompileEgressRuleset(policy, s.resolveNode, opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sum := sha256.Sum256([]byte(plan))
	policy.LastPlanSHA = hex.EncodeToString(sum[:])
	policy.LastError = ""
	if err := s.store.UpsertNetPolicy(policy); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    policy.TargetNodeID,
		Plugin:    "nftpolicy",
		Action:    nftPolicyApprovalAction(s.publicURL),
		Plan:      plan,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: policy.TargetNodeID,
		Action: "network.policy.plan",
		Scope:  "netpolicy:admin",
		Metadata: map[string]string{
			"approval_id": approval.ID,
			"plan_sha":    policy.LastPlanSHA,
		},
	})
	writeJSON(w, http.StatusOK, toApprovalView(approval))
}

func (s *Server) netPolicyCompileOptions() (netpolicy.CompileOptions, error) {
	if s.publicURL == "" {
		return netpolicy.CompileOptions{}, errors.New("public_url is required for netpolicy apply")
	}
	u, err := url.Parse(s.publicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return netpolicy.CompileOptions{}, fmt.Errorf("invalid public_url %q", s.publicURL)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return netpolicy.CompileOptions{}, errors.New("public_url must be a scheme+host base URL without path, query, or fragment")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return netpolicy.CompileOptions{}, fmt.Errorf("public_url scheme %q is not supported", u.Scheme)
	}
	host := u.Hostname()
	addr, err := netip.ParseAddr(host)
	if err == nil {
		if u.Scheme == "http" && !addr.IsLoopback() {
			return netpolicy.CompileOptions{}, errors.New("public_url must use https for non-loopback netpolicy apply")
		}
		port := 0
		if rawPort := u.Port(); rawPort != "" {
			port, err = strconv.Atoi(rawPort)
			if err != nil || port < 1 || port > 65535 {
				return netpolicy.CompileOptions{}, fmt.Errorf("invalid public_url port %q", rawPort)
			}
		} else if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
		if addr.Is4() {
			return netpolicy.CompileOptions{ControlPlaneIPv4: addr, ControlPlanePort: port}, nil
		}
		if addr.Is6() && !addr.Is4In6() {
			return netpolicy.CompileOptions{ControlPlaneIPv6: addr, ControlPlanePort: port}, nil
		}
		return netpolicy.CompileOptions{}, fmt.Errorf("public_url host %q must be IPv4, IPv6, or an HTTPS hostname for netpolicy apply", host)
	}
	if u.Scheme != "https" {
		return netpolicy.CompileOptions{}, errors.New("public_url must use https when host is not an IPv4 literal")
	}
	host, err = normalizeControlPlaneHost(host)
	if err != nil {
		return netpolicy.CompileOptions{}, err
	}
	port := 0
	if rawPort := u.Port(); rawPort != "" {
		port, err = strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			return netpolicy.CompileOptions{}, fmt.Errorf("invalid public_url port %q", rawPort)
		}
	} else if u.Scheme == "https" {
		port = 443
	}
	return netpolicy.CompileOptions{ControlPlaneHost: host, ControlPlanePort: port}, nil
}

func normalizeControlPlaneHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid public_url hostname %q", host)
	}
	if !controlPlaneHostRe.MatchString(host) {
		return "", fmt.Errorf("invalid public_url hostname %q", host)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 {
			return "", fmt.Errorf("invalid public_url hostname %q: label too long", host)
		}
	}
	return host, nil
}

func sameNetPolicyIntent(a, b model.NetPolicy) bool {
	return a.Enabled == b.Enabled && reflect.DeepEqual(a.Rules, b.Rules)
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
