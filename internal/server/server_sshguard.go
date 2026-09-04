package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
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

// sshGuardApprovalStaleCode labels a dismissal in the audit trail.
const sshGuardApprovalStaleCode = "sshguard_approval_superseded"

// sshGuardSupersededMark is the phrase dismissibleSSHGuardApprovalReason writes
// and sshGuardApprovalSuperseded reads back. The dismissal keeps its stale code
// only in the audit row, so the reason text is the record's own memory of why
// it was retired, and the one thing a later reader can key on.
const sshGuardSupersededMark = "approval superseded: approved but never applied"

// sshGuardApprovalSuperseded reports whether a dismissed SSH Guard approval was
// retired as superseded: approved, dispatched, its task run, and the record left
// at approved because nothing carried the result back at the time. The
// dismissal retired the record. It did not touch the node, so what the arm
// wrote there is still what the node runs unless a later arm replaced it.
func sshGuardApprovalSuperseded(a model.Approval) bool {
	return isSSHGuardApproval(a) && a.Status == approvalStatusDismissed && strings.Contains(a.Reason, sshGuardSupersededMark)
}

// dismissibleSSHGuardApprovalReason decides whether an SSH Guard approval can
// be retired without being applied, and what the record should say.
//
// An approval that was approved but never reached `applied` is a dead end: the
// approve endpoint is idempotent, so re-approving it dispatches nothing, and
// nothing else will ever move it. Before the task result was wired back into
// the approval, this was every SSH Guard approval on this fleet, including the
// ones whose apply had failed: sixty records sitting in a state that looked
// like pending work and could not be cleared. Rejecting is not available
// either, because reject only acts on a pending approval.
//
// The bar is deliberately narrow. A pending approval must be approved or
// rejected on its merits, an applied one is history, and an approval with an
// apply in flight is refused by the caller. What is left is exactly the dead
// end.
func (s *Server) dismissibleSSHGuardApprovalReason(approval model.Approval, note string) (string, bool) {
	if approval.Status != model.ApprovalApproved {
		return "", false
	}
	stage := "arm"
	if approval.Action == sshGuardConfirmAction {
		stage = "confirm"
	}
	reason := fmt.Sprintf("SSH Guard %s %s, and an approval cannot be re-dispatched. Re-plan if this node still needs the change.", stage, sshGuardSupersededMark)
	if note != "" {
		reason = reason + " " + note
	}
	return reason, true
}

// sshGuardNodeReality assembles what the lint reasons about from two
// independent sources: what the node says it is running, and what netguard
// would put in front of it.
func (s *Server) sshGuardNodeReality(nodeID string) sshguard.NodeReality {
	out := sshguard.NodeReality{}
	// Both halves matter. A terminal capability on a node that stopped
	// reporting is a fallback on paper, and this is the field a profile leans
	// on when it gates SSH with no address allowlist.
	if node, ok := s.store.Node(nodeID); ok && node.Online {
		// Prefer what the agent actually reports over what the installer was
		// told to configure: the launch profile is intent, the runtime snapshot
		// is fact, and only the second one is a fallback you can use.
		if runtime := s.agentRuntimeSnapshot(nodeID); runtime != nil {
			out.TerminalAvailable = runtime.AllowTerminal
		} else if node.AgentLaunch != nil {
			out.TerminalAvailable = node.AgentLaunch.AllowTerminal
		}
	}
	if snapshot := s.guardRealityForLint(nodeID); snapshot != nil {
		out.Reported = true
		for _, listener := range snapshot.Listeners {
			if listener.Protocol == "tcp" {
				out.ListeningTCPPorts = append(out.ListeningTCPPorts, listener.Port)
			}
		}
		out.SSHPorts = sshListeningPorts(snapshot)
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
	// OutOfBandFallback lets a knock profile stand on the node's Lattice
	// terminal instead of an address allowlist. It is checked against the
	// node's reported capability, not believed.
	OutOfBandFallback bool `json:"out_of_band_fallback"`
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

	// Advanced. Everything above covers an ordinary host; these exist so an
	// unusual one can be described instead of the product being taught about
	// it. All of them are omissible and all of them override rather than merge.
	//
	// GatePorts replaces the ports the gate covers, which are otherwise derived
	// from what sshd reports. KnockPorts replaces the drawn sequence, which is
	// otherwise crypto/rand: supply one only if something outside Lattice has
	// to agree on it, because a chosen sequence is only as secret as wherever
	// it was chosen. KnockOpenForSec and KnockSeqTimeoutSec tune the two
	// timings.
	GatePorts          []int  `json:"gate_ports"`
	KnockPorts         []int  `json:"knock_ports"`
	KnockOpenFor       string `json:"knock_open_for"`
	KnockSeqTimeoutSec int    `json:"knock_seq_timeout_sec"`

	// Hardening overrides. Zero values mean "use the verified default", so a
	// caller that sends only node_id and ssh_port gets the configuration that
	// was tested on the reference host.
	LoginGraceTimeSec int    `json:"login_grace_time_sec"`
	MaxAuthTries      int    `json:"max_auth_tries"`
	MaxStartups       string `json:"max_startups"`
	PermitRootLogin   string `json:"permit_root_login"`
}

// sshListeningPorts picks out the ports a shell daemon is actually bound to.
//
// It reuses the daemon names netguard's lockout lint already uses, and for the
// same reason: assuming tcp/22 is an assumption, and measuring this fleet found
// it wrong on three machines of thirteen, where sshd runs on 3434. Gating 22
// there protects nothing and still reports success. A loopback binding is
// skipped because gating it would guard nothing reachable.
func sshListeningPorts(reality *model.GuardNodeReality) []int {
	if reality == nil {
		return nil
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, l := range reality.Listeners {
		if l.Protocol != "tcp" || l.Port <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(l.Process))
		if !strings.HasPrefix(name, "sshd") && !strings.HasPrefix(name, "dropbear") {
			continue
		}
		if strings.HasPrefix(l.Address, "127.") || l.Address == "::1" {
			continue
		}
		if seen[l.Port] {
			continue
		}
		seen[l.Port] = true
		ports = append(ports, l.Port)
	}
	sort.Ints(ports)
	return ports
}

func (req sshGuardPlanRequest) profile(existingSSHPorts []int) (sshguard.Profile, error) {
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
		NodeID:            req.NodeID,
		GatePorts:         req.GatePorts,
		ExistingSSHPorts:  existingSSHPorts,
		SSHPort:           req.SSHPort,
		KeepLegacyPort:    keepLegacy,
		Hardening:         hardening,
		MgmtSources:       req.MgmtSources,
		OutOfBandFallback: req.OutOfBandFallback,
		ConfirmWindowSec:  req.ConfirmWindowSec,
	}
	enableKnock := req.SSHPort != 0
	if req.EnableKnock != nil {
		enableKnock = *req.EnableKnock
	}
	if enableKnock {
		ports := req.KnockPorts
		if len(ports) == 0 {
			// Drawn, not derived. A sequence derived from the node id is only
			// as secret as the derivation, and the derivation lives in a
			// repository.
			drawn, err := sshguard.NewKnockSequence()
			if err != nil {
				return sshguard.Profile{}, err
			}
			ports = drawn
		}
		seqTimeout := req.KnockSeqTimeoutSec
		if seqTimeout == 0 {
			seqTimeout = 15
		}
		openFor := strings.TrimSpace(req.KnockOpenFor)
		if openFor == "" {
			openFor = "12h"
		}
		profile.Knock = &sshguard.KnockPolicy{Ports: ports, SeqTimeoutSec: seqTimeout, OpenFor: openFor}
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
	// Enrolment gate, on the arm path only.
	//
	// SSH Guard decides who can reach a machine over SSH, so which machines are
	// in scope is a decision an operator makes per node, not a consequence of
	// which rows they selected. Checked before the plan is rendered, so an
	// out-of-scope node never produces an approval that someone could later wave
	// through without noticing where it came from.
	//
	// Deliberately not on handleSSHGuardConfirm: confirm cancels the revert timer
	// on an already-armed node. Refusing it because the node was excluded after
	// arming would strand that node mid-operation, waiting on a timer to undo
	// work an operator was trying to finish. A gate belongs on the step that
	// starts something, not on the one that completes it.
	if !s.requireNodeCapability(w, req.NodeID, sshGuardPlugin) {
		return
	}
	profile, err := req.profile(s.sshGuardNodeReality(req.NodeID).SSHPorts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Only so the plan can print a knock command that is copyable. The value is
	// agent-reported, and the renderer accepts it only if it parses as an IP.
	profile.Address = node.PublicIP
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

// handleSSHGuardTaskResult advances an SSH Guard approval once its apply task
// reports.
//
// Without this the approval stopped at `approved` forever. The work ran, the
// task result was stored, and nothing carried that back: 60 approvals across 24
// nodes sat looking un-applied a week after their tasks had finished. Every
// other plugin here does this; sshguard was wired for planning and approving
// and never for the result.
//
// It is not only cosmetic. `applied` on the arm is what says the revert timer
// is now running, which is the one state on this capability with a deadline. A
// status that never advances makes that state unreachable and leaves an
// operator with no way to tell, from the control plane, whether the hardening
// is live.
func (s *Server) handleSSHGuardTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now().UTC()
	}
	stage := "arm"
	if approval.Action == sshGuardConfirmAction {
		stage = "confirm"
	}
	metadata := map[string]string{
		"approval_id": approval.ID,
		"task_id":     task.ID,
		"stage":       stage,
		"plan_sha":    approvalPlanSHA(approval),
	}
	if result.Error == "" && result.ExitCode == 0 {
		approval.Status = model.ApprovalApplied
		approval.Reason = ""
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("mark sshguard approval applied: %w", err)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   approval.NodeID,
			Action:   "sshguard." + stage + ".applied",
			Decision: "allow",
			Metadata: metadata,
		})
		return nil
	}
	// A failed arm is the case the automatic revert exists for: the node is
	// restoring itself, and the approval must not keep claiming it is armed.
	reason := taskFailureSummary(result)
	if err := s.rejectApprovalWithReason(approval, reason); err != nil {
		return fmt.Errorf("mark sshguard approval rejected: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   approval.NodeID,
		Action:   "sshguard." + stage + ".failed",
		Decision: "deny",
		Reason:   reason,
		Metadata: metadata,
	})
	return nil
}
