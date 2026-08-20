package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
)

// SSH Guard is the one-click hardening surface: an sshd drop-in, an
// independent nftables gate, and an optional port-knock sequence, applied
// through the existing approval pipeline.
//
// It is deliberately its own plugin rather than a netguard action. The two
// touch nftables but disagree on almost everything else: netguard's renderer
// cannot express a named set with a timeout, its rollback flushes the whole
// machine's ruleset, and its lockout lint reasons about static acceptance in a
// way that a knock ruleset invalidates. Sharing the plugin id would have meant
// sharing all three.
const (
	sshGuardPlugin        = "sshguard"
	sshGuardArmAction     = "sshguard-arm:v1"
	sshGuardConfirmAction = "sshguard-confirm:v1"
)

func isSSHGuardApproval(approval model.Approval) bool {
	return approval.Plugin == sshGuardPlugin &&
		(approval.Action == sshGuardArmAction || approval.Action == sshGuardConfirmAction)
}

// sshGuardNodeReality assembles what the lint reasons about from two
// independent sources: what the node says it is running, and what netguard
// would put in front of it.
func (s *Server) sshGuardNodeReality(nodeID string) sshguard.NodeReality {
	out := sshguard.NodeReality{}
	if snapshot := s.guardRealityForLint(nodeID); snapshot != nil {
		out.Reported = true
		for _, listener := range snapshot.Listeners {
			if listener.Protocol == "tcp" {
				out.ListeningTCPPorts = append(out.ListeningTCPPorts, listener.Port)
			}
		}
	}
	binding, ok := s.store.NodeGuardBinding(nodeID)
	if !ok || binding.NodeID == "" {
		return out
	}
	out.ManagedByNetGuard = true
	// GenerateNFTPlan emits `policy drop` unconditionally, so any node with a
	// guard binding has a default-deny chain waiting at a higher priority than
	// the knock table. That is precisely the case the override finding exists
	// for.
	out.GuardPolicyDrop = true
	input, err := s.compileInputForSystem(nodeID)
	if err != nil {
		return out
	}
	plan, err := netguard.Compile(input)
	if err != nil {
		return out
	}
	out.GuardAcceptedTCPPorts, out.GuardAcceptsAllTCP = guardAcceptedTCPPorts(plan)
	return out
}

// guardAcceptedTCPPorts collects every TCP port a compiled guard plan can
// accept. It is deliberately generous in the same direction netguard's own
// lint is: a rule with no port list accepts all ports, and an any-protocol
// accept covers TCP. Being generous here means the override finding fires only
// when there is genuinely no acceptance, which keeps it a signal.
func guardAcceptedTCPPorts(plan network.NFTPlan) ([]int, bool) {
	ports := append([]int{}, plan.PublicTCP...)
	ports = append(ports, plan.WireGuardTCP...)
	for _, rule := range plan.InputRules {
		if rule.Action != network.NFTActionAccept {
			continue
		}
		switch rule.Protocol {
		case network.NFTProtoAny:
			return ports, true
		case network.NFTProtoTCP:
			if len(rule.Ports) == 0 {
				return ports, true
			}
			ports = append(ports, rule.Ports...)
		}
	}
	return ports, false
}

type sshGuardPlanRequest struct {
	NodeID         string   `json:"node_id"`
	SSHPort        int      `json:"ssh_port"`
	KeepLegacyPort *bool    `json:"keep_legacy_port"`
	MgmtSources    []string `json:"mgmt_sources"`
	// EnableKnock defaults to true when ssh_port is set. Turning it off yields a
	// profile that hardens sshd and shrinks the ports to the management
	// sources, which is a legitimate and materially safer configuration.
	EnableKnock      *bool `json:"enable_knock"`
	ConfirmWindowSec int   `json:"confirm_window_sec"`
	// AcceptFindings carries the plan past blocking lint findings. It exists
	// because the override finding can be a false alarm on a node whose guard
	// is about to change too, and it records the decision in the audit trail
	// rather than letting the operator edit the lint away.
	AcceptFindings bool `json:"accept_findings"`

	// Hardening overrides. Zero values mean "use the verified default", so a
	// caller that sends only node_id and ssh_port gets the configuration that
	// was tested on the reference host.
	LoginGraceTimeSec int    `json:"login_grace_time_sec"`
	MaxAuthTries      int    `json:"max_auth_tries"`
	MaxStartups       string `json:"max_startups"`
	PermitRootLogin   string `json:"permit_root_login"`
}

func (req sshGuardPlanRequest) profile() (sshguard.Profile, error) {
	hardening := sshguard.DefaultHardening()
	if req.LoginGraceTimeSec != 0 {
		hardening.LoginGraceTimeSec = req.LoginGraceTimeSec
	}
	if req.MaxAuthTries != 0 {
		hardening.MaxAuthTries = req.MaxAuthTries
	}
	if req.MaxStartups != "" {
		hardening.MaxStartups = req.MaxStartups
	}
	if req.PermitRootLogin != "" {
		hardening.PermitRootLogin = req.PermitRootLogin
	}
	keepLegacy := true
	if req.KeepLegacyPort != nil {
		keepLegacy = *req.KeepLegacyPort
	}
	profile := sshguard.Profile{
		NodeID:           req.NodeID,
		SSHPort:          req.SSHPort,
		KeepLegacyPort:   keepLegacy,
		Hardening:        hardening,
		MgmtSources:      req.MgmtSources,
		ConfirmWindowSec: req.ConfirmWindowSec,
	}
	enableKnock := req.SSHPort != 0
	if req.EnableKnock != nil {
		enableKnock = *req.EnableKnock
	}
	if enableKnock {
		ports, err := sshguard.NewKnockSequence()
		if err != nil {
			return sshguard.Profile{}, err
		}
		profile.Knock = &sshguard.KnockPolicy{Ports: ports, SeqTimeoutSec: 15, OpenFor: "12h"}
	}
	if profile.ConfirmWindowSec == 0 {
		profile.ConfirmWindowSec = sshguard.DefaultConfirmWindowSec
	}
	return profile, profile.Validate()
}

func (s *Server) handleSSHGuardPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req sshGuardPlanRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "sshguard:admin", req.NodeID) {
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
		return
	}
	// Refuse a node that does not exist rather than minting an approval that can
	// never apply. The scope check above passes for an unrestricted admin
	// regardless of whether the id names anything.
	node, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	profile, err := req.profile()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	findings := sshguard.LintProfile(profile, s.sshGuardNodeReality(req.NodeID))
	if sshguard.Blocking(findings) && !req.AcceptFindings {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":    "plan blocked by lint findings",
			"findings": findings,
		})
		return
	}
	plan, err := sshguard.RenderArmPlan(profile, node.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    req.NodeID,
		Plugin:    sshGuardPlugin,
		Action:    sshGuardArmAction,
		Plan:      plan,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	approval, err = s.submitApproval(r.Context(), approval)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	metadata := map[string]string{"approval_id": approval.ID, "stage": string(sshguard.StageArm)}
	if sshguard.Blocking(findings) {
		metadata["findings_accepted"] = "true"
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), NodeID: req.NodeID, Action: "sshguard.findings.accepted", Scope: "sshguard:admin",
			Metadata: map[string]string{"node_id": req.NodeID, "approval_id": approval.ID},
		})
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "sshguard.plan", Scope: "network:plan", Metadata: metadata,
	})
	writeJSON(w, http.StatusOK, map[string]any{"approval": approval, "findings": findings})
}

// handleSSHGuardConfirm creates the second approval, whose only effect is to
// cancel the pending automatic revert.
//
// It is a separate approval rather than a flag on the first one because the
// two decisions are made at different times by a human who has done something
// in between: opened a new connection over the new path and gotten a shell.
// Collapsing them into one click would remove the only evidence that the
// change is survivable.
func (s *Server) handleSSHGuardConfirm(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "sshguard:admin", req.NodeID) {
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
		return
	}
	node, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	plan, err := sshguard.RenderConfirmPlan(req.NodeID, node.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    req.NodeID,
		Plugin:    sshGuardPlugin,
		Action:    sshGuardConfirmAction,
		Plan:      plan,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	approval, err = s.submitApproval(r.Context(), approval)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "sshguard.confirm.plan", Scope: "network:plan",
		Metadata: map[string]string{"approval_id": approval.ID, "stage": string(sshguard.StageConfirm)},
	})
	writeJSON(w, http.StatusOK, map[string]any{"approval": approval})
}
