package server

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
)

// Reading a node's knock sequence back.
//
// The question this answers came from an operator standing at a terminal
// unable to reach a machine: the console showed him SSH Guard was armed and
// would not tell him how to knock, so the sequence he needed was only in an
// operations note. The console was not missing the data. It had it and said
// nothing.
//
// There is no knock store, and this deliberately does not add one. The
// sequence is drawn at plan time and written into the arm approval's plan
// document, which is the same document ApplyScriptFromPlan parses to build the
// script that writes /etc/knockd.conf on the host. That document is the
// control plane's record of the sequence, so reading it back is reading the
// authority the node was configured from rather than a cache that can drift.
//
// Two endpoints, and the split is the point:
//
//   - knockState says whether a sequence is known and what shape it has, and
//     carries no ports. It is the honest answer the page needs in order to
//     stop being silent, and it is safe for any reader who could review the
//     approval anyway.
//   - reveal returns the ports, behind the same step-up grant the sing-box
//     line reveal and the task script reveal use, and writes an audit row.
//
// Scope is sshguard:read plus network:plan, which is exactly what
// approvalPrimaryScopeAllows already requires to read an SSH Guard plan. That
// is deliberate. The sequence is already readable by that pair through the
// approvals API, so requiring more here would not protect anything: it would
// only push an operator to the unaudited path. What the reveal adds over that
// path is the second factor and the audit row, and it should therefore be the
// easiest correct way to get the value, not the hardest.

// knockKnowledge names what the control plane can say about a node's sequence.
type knockKnowledge string

const (
	// knockInstalled: an arm plan carrying a sequence reached applied.
	knockInstalled knockKnowledge = "installed"
	// knockInstalledSuperseded: the arm that carried the sequence to the node
	// was approved and dispatched, and its record was later dismissed as
	// superseded because nothing had carried the task result back at the
	// time. The dismissal retired the record, not the change on the node.
	knockInstalledSuperseded knockKnowledge = "installed_superseded"
	// knockPlanned: an arm plan carrying a sequence exists but has not applied.
	knockPlanned knockKnowledge = "planned"
	// knockNoKnock: SSH Guard installed a firewall here with knocking turned
	// off, which retires any sequence an earlier arm had installed.
	knockNoKnock knockKnowledge = "no_knock"
	// knockUnknown: no SSH Guard plan ever carried a knock to this node, so if
	// the node is knocking, it was not this system that told it to.
	knockUnknown knockKnowledge = "unknown"
)

// sshGuardKnockState is what the control plane knows about one node's knock
// sequence. Sequence is unexported and never serialized; the reveal handler
// reads it, the status handler does not.
type sshGuardKnockState struct {
	Knowledge  knockKnowledge
	ApprovalID string
	AppliedAt  time.Time
	// Confirmed reports whether the confirm approval that followed this arm
	// applied. An arm that applied and was never confirmed may have been
	// undone by its own revert timer, which the control plane does not
	// observe, so the page must not claim the sequence is in force.
	Confirmed bool
	SSHPort   int
	Address   string
	Sequence  sshguard.KnockSequence
	// Rejected is set when this node has SSH Guard arm plans but none that
	// govern it: every one was rejected or dismissed. The knowledge is still
	// unknown, because no sequence reached the node, but "there was never a
	// plan" and "the plans there were all died" are different things to tell
	// someone who cannot get in.
	Rejected bool
	// HardenedOnly is set when SSH Guard reached this node but every arm that
	// did was hardening only: an sshd drop-in, no firewall, no knockd. Those
	// arms say nothing about knocking either way, so the knowledge is unknown
	// for a different reason than "no plan".
	HardenedOnly bool
	// ParseError records a plan this code could not read. Reported rather than
	// swallowed: a plan that will not parse is a sequence an operator is going
	// to go looking for in the note, and silence would send him there without
	// saying why.
	ParseError string
}

// sshGuardKnockStateFor picks the arm plan that describes the node's current
// knock configuration and reads the sequence out of it.
//
// The knowledge is layered, because the node is. Each arm writes only what its
// plan carries: a hardening-only arm writes the sshd drop-in and leaves knockd
// and the knock table exactly as they were, so it cannot retire a sequence an
// earlier arm installed. The arm that governs the knock is therefore the newest
// one that carried a firewall AND reached the node, not the newest one that
// applied. Reading it the other way reported "no knock" for five nodes that
// were still gating SSH on a sequence from three weeks earlier.
//
// Reaching the node means one of two things. Applied is the plain case. The
// other is a record dismissed as superseded: approved and dispatched before
// task results were wired back into approvals, then retired by a cleanup that
// could not move it out of approved. That dismissal touched the record, not
// the host, so such an arm counts as reached when a confirm was dispatched
// after it: the confirm is the operator saying he got in over the new path,
// which is the evidence the arm's own status never recorded. A superseded arm
// with nothing after it may have failed and reverted, and is not counted.
//
// An arm still pending is reported as planned rather than installed, because
// knocking a sequence that was never applied fails silently and looks like
// the sequence is wrong.
func (s *Server) sshGuardKnockStateFor(nodeID string) sshGuardKnockState {
	approvals := s.store.Approvals()
	arms := make([]model.Approval, 0, 4)
	confirms := make([]model.Approval, 0, 4)
	for _, a := range approvals {
		if a.NodeID != nodeID || a.Plugin != sshGuardPlugin {
			continue
		}
		switch a.Action {
		case sshGuardArmAction:
			arms = append(arms, a)
		case sshGuardConfirmAction:
			confirms = append(confirms, a)
		}
	}
	if len(arms) == 0 {
		return sshGuardKnockState{Knowledge: knockUnknown}
	}
	// Authoring order, newest first. CreatedAt is the one timestamp that means
	// the same thing on every record: UpdatedAt is when an applied arm applied,
	// but on a dismissed one it is the day of the cleanup, which says nothing
	// about the node.
	sort.SliceStable(arms, func(i, j int) bool {
		return arms[i].CreatedAt.After(arms[j].CreatedAt)
	})

	node, _ := s.store.Node(nodeID)
	read := func(a model.Approval) (sshGuardKnockState, sshguard.Artifacts, bool) {
		art, err := sshguard.ParseApprovalPlan(a.Plan)
		if err != nil {
			return sshGuardKnockState{ApprovalID: a.ID, ParseError: err.Error()}, art, false
		}
		out := sshGuardKnockState{
			ApprovalID: a.ID,
			AppliedAt:  a.UpdatedAt,
			SSHPort:    art.SSHPort,
			Address:    node.PublicIP,
		}
		if strings.TrimSpace(art.KnockdConf) == "" {
			out.Knowledge = knockNoKnock
			return out, art, true
		}
		seq, err := sshguard.ParseKnockdConf(art.KnockdConf)
		if err != nil {
			out.ParseError = err.Error()
			return out, art, false
		}
		out.Sequence = seq
		return out, art, true
	}
	// confirmsFor reports the confirms filed for one arm: authored after it and
	// before the next arm that was dispatched. A confirm belongs to the arm
	// it followed, so the confirm of a later hardening-only re-arm must not
	// be read as proof that an older knock arm was confirmed.
	confirmsFor := func(arm model.Approval, until time.Time) (dispatched, applied bool) {
		for _, c := range confirms {
			if !c.CreatedAt.After(arm.CreatedAt) {
				continue
			}
			if !until.IsZero() && !c.CreatedAt.Before(until) {
				continue
			}
			switch {
			case c.Status == model.ApprovalApplied:
				dispatched, applied = true, true
			case sshGuardApprovalSuperseded(c):
				dispatched = true
			}
		}
		return dispatched, applied
	}

	hardenedOnly := false
	until := time.Time{}
	for _, a := range arms {
		applied := a.Status == model.ApprovalApplied
		if !applied && !sshGuardApprovalSuperseded(a) {
			// Pending, approved, rejected: nothing this arm carried is on the
			// node yet, or ever.
			continue
		}
		window := until
		until = a.CreatedAt
		state, art, ok := read(a)
		if !ok {
			return state
		}
		if strings.TrimSpace(art.KnockNFT) == "" {
			// Hardening only. This arm wrote the drop-in and nothing else, so
			// it neither supplies a knock nor retires one.
			hardenedOnly = true
			continue
		}
		dispatched, confirmed := confirmsFor(a, window)
		if !applied && !dispatched {
			continue
		}
		if state.Knowledge == knockNoKnock {
			// A firewall without a sequence. The table it installs has no
			// allowed set for knockd to add to, so whatever knocked before
			// this arm no longer opens anything.
			return state
		}
		state.Confirmed = confirmed
		if applied {
			state.Knowledge = knockInstalled
			return state
		}
		// The record's UpdatedAt is the dismissal, not the apply, and the
		// apply time was never written anywhere. Zero is more honest than
		// either.
		state.Knowledge = knockInstalledSuperseded
		state.AppliedAt = time.Time{}
		return state
	}
	// Nothing that reached the node carried a firewall. A plan still waiting on
	// a decision says what was asked for, which is worth reporting so the page
	// can distinguish "not set up yet" from "this system has never touched SSH
	// Guard here".
	//
	// A rejected or dismissed arm is not that. Its sequence was never written
	// to the node and never will be, so reporting it as planned would tell an
	// operator to knock ports nothing is listening for.
	for _, a := range arms {
		if a.Status != model.ApprovalPending && a.Status != model.ApprovalApproved {
			continue
		}
		state, _, ok := read(a)
		if !ok {
			return state
		}
		if state.Knowledge != knockNoKnock {
			state.Knowledge = knockPlanned
		}
		state.AppliedAt = time.Time{}
		return state
	}
	if hardenedOnly {
		return sshGuardKnockState{Knowledge: knockUnknown, HardenedOnly: true}
	}
	return sshGuardKnockState{Knowledge: knockUnknown, Rejected: true}
}

// knockStateNote is the sentence the console shows. It is written here rather
// than in the console so the API and the page cannot disagree about what the
// control plane knows, and so an agent reading the endpoint gets the same
// answer a person does.
func knockStateNote(state sshGuardKnockState) string {
	if state.ParseError != "" {
		return "This node's SSH Guard plan could not be read, so the control plane cannot tell you the knock sequence. The sequence is still on the node in /etc/knockd.conf."
	}
	switch state.Knowledge {
	case knockInstalled:
		if state.Confirmed {
			return "The control plane knows this node's knock sequence. It was applied and confirmed, so it is the sequence the node is running."
		}
		return "The control plane knows the knock sequence from the arm that was applied. That arm was never confirmed, so its automatic revert may have removed it from the node since."
	case knockInstalledSuperseded:
		if state.Confirmed {
			return "The control plane knows this node's knock sequence from an arm record that was later dismissed as superseded. The dismissal retired the record, not the change: the arm was approved and dispatched, its confirm applied, and no later plan has replaced the knock since. This is the sequence the node was last told to run."
		}
		return "The control plane knows this node's knock sequence from an arm record that was later dismissed as superseded. The dismissal retired the record, not the change: the arm and a confirm after it were both approved and dispatched before apply results were recorded on approvals, so neither outcome was written back. No later plan has replaced the knock since. Treat this as the sequence the node was last told to run, and prove it with a knock before relying on it."
	case knockPlanned:
		return "An SSH Guard plan for this node carries a knock sequence, but it has not been applied. The node is not knocking on it yet."
	case knockNoKnock:
		return "SSH Guard is set up on this node without port knocking. There is no sequence to show; reach SSH from a management source."
	default:
		if state.HardenedOnly {
			return "SSH Guard hardened sshd on this node without installing a firewall, so no plan here ever carried a knock sequence. If this node knocks, it was configured outside Lattice and the sequence is only wherever that was recorded."
		}
		if state.Rejected {
			return "Every SSH Guard plan for this node was rejected or dismissed, so none of their sequences ever reached it. The control plane knows no sequence that opens this node."
		}
		return "The control plane has no SSH Guard plan for this node, so it does not know a knock sequence. If this node knocks, it was configured outside Lattice and the sequence is only wherever that was recorded."
	}
}

// knockRevealable says whether a reveal would return anything for this
// knowledge, so the page can decide between offering the button and
// explaining its absence.
func knockRevealable(k knockKnowledge) bool {
	return k == knockInstalled || k == knockInstalledSuperseded || k == knockPlanned
}

func (s *Server) sshGuardKnockScopes(w http.ResponseWriter, p principal, nodeID string) bool {
	// The pair approvalPrimaryScopeAllows requires to read an SSH Guard plan.
	// Kept identical on purpose: this endpoint must not be a way around that
	// gate, and must not be stricter than it either.
	if !s.requireNodeScope(w, p, "sshguard:read", nodeID) {
		return false
	}
	return s.requireNodeScope(w, p, "network:plan", nodeID)
}

// handleSSHGuardKnockState reports whether the control plane knows this node's
// knock sequence, without disclosing it.
//
// This is the half an agent can have. It carries no ports, so it needs no
// second factor and works from a bearer token: a plan can discover that a node
// has a sequence, that it applied, and where it is recorded, and can act on
// all of that. Only the disclosure itself is held back.
func (s *Server) handleSSHGuardKnockState(w http.ResponseWriter, r *http.Request, p principal) {
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
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.sshGuardKnockScopes(w, p, req.NodeID) {
		return
	}
	state := s.sshGuardKnockStateFor(req.NodeID)
	gate := sshGuardKnockGate(s.guardRealityForLint(req.NodeID))
	out := map[string]any{
		"ok":        true,
		"node_id":   req.NodeID,
		"knowledge": string(state.Knowledge),
		"note":      knockStateNoteWithGate(state, gate),
		// What the node itself reports: the inet lattice_knock table is on
		// it right now. Independent of the approvals, so a gate the timer
		// was supposed to remove and did not still shows as present.
		"gate_present": gate,
		// Whether a reveal would return anything, so the page can decide
		// between offering the button and explaining its absence.
		"revealable": knockRevealable(state.Knowledge),
		// Named so the console never has to hardcode the fact that the reveal
		// needs a second factor.
		"requires_step_up": true,
		"interactive_only": true,
	}
	if state.ApprovalID != "" {
		out["approval_id"] = state.ApprovalID
	}
	if !state.AppliedAt.IsZero() {
		out["applied_at"] = state.AppliedAt
	}
	if state.Knowledge == knockInstalled || state.Knowledge == knockInstalledSuperseded {
		out["confirmed"] = state.Confirmed
	}
	if state.ParseError != "" {
		out["plan_unreadable"] = state.ParseError
	}
	// Shape, not secret: how many ports, how long the sequence has to arrive,
	// how long the door stays open. None of it narrows a guess at the ports.
	if n := len(state.Sequence.Ports); n > 0 {
		out["port_count"] = n
		out["seq_timeout_sec"] = state.Sequence.SeqTimeoutSec
		out["open_for"] = state.Sequence.OpenFor
	}
	if state.SSHPort > 0 {
		out["ssh_port"] = state.SSHPort
	}
	// Mid-rotation: the arm kept the previous sequence alive and no confirm
	// has retired it yet, so the knock the operator already holds still works.
	if len(state.Sequence.PreviousPorts) > 0 && !state.Confirmed {
		out["previous_honoured"] = true
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSSHGuardRevealKnock returns the knock sequence once, to a person.
//
// It follows handleRevealSingBoxLine: scope, then step-up grant, then an audit
// row naming the action, then the value. The audit row records that the
// sequence was revealed and by whom. It does not record the sequence, and
// neither does anything else on this path: the ports are put in the response
// body and nowhere else.
func (s *Server) handleSSHGuardRevealKnock(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID      string `json:"node_id"`
		StepUpGrant string `json:"step_up_grant"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.sshGuardKnockScopes(w, p, req.NodeID) {
		return
	}
	// requireStepUpGrant refuses a bearer principal already, but with a
	// sentence about sessions that does not say why this endpoint in
	// particular is human-only. An agent that asked for a way into a machine
	// deserves the actual reason and a pointer to the half it can have.
	if p.viaBearer {
		writeError(w, http.StatusForbidden, errors.New("the knock sequence is revealed only to an interactive session that can satisfy a second factor; use /api/sshguard/knock to learn whether a sequence exists and /api/network/approvals to read the plan that installed it"))
		return
	}
	if !s.requireStepUpGrant(w, p, strings.TrimSpace(req.StepUpGrant), "sshguard.knock.reveal") {
		return
	}
	state := s.sshGuardKnockStateFor(req.NodeID)
	if state.ParseError != "" {
		writeError(w, http.StatusConflict, errors.New("this node's SSH Guard plan could not be read: "+state.ParseError))
		return
	}
	switch state.Knowledge {
	case knockInstalled, knockInstalledSuperseded, knockPlanned:
	case knockNoKnock:
		writeError(w, http.StatusNotFound, errors.New("SSH Guard is applied on this node without port knocking, so there is no sequence"))
		return
	default:
		writeError(w, http.StatusNotFound, errors.New("the control plane has no SSH Guard plan for this node and does not know a knock sequence"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: req.NodeID,
		Action: "sshguard.knock.reveal",
		Scope:  "sshguard:read",
		// approval_id and knowledge, never the ports.
		Metadata: map[string]string{
			"approval_id": state.ApprovalID,
			"knowledge":   string(state.Knowledge),
			"confirmed":   strconv.FormatBool(state.Confirmed),
		},
	})
	gate := sshGuardKnockGate(s.guardRealityForLint(req.NodeID))
	out := map[string]any{
		"ok":          true,
		"node_id":     req.NodeID,
		"knowledge":   string(state.Knowledge),
		"approval_id": state.ApprovalID,
		// The same sentence the state endpoint shows, so a sequence read out
		// of a superseded record arrives with the caveat attached rather than
		// looking like one the control plane watched apply.
		"note":            knockStateNoteWithGate(state, gate),
		"gate_present":    gate,
		"confirmed":       state.Confirmed,
		"ports":           state.Sequence.Ports,
		"seq_timeout_sec": state.Sequence.SeqTimeoutSec,
		"open_for":        state.Sequence.OpenFor,
		"ssh_port":        state.SSHPort,
		"address":         state.Address,
		"command":         state.Sequence.KnockCommand(state.Address, state.SSHPort),
		// What a rotation request hands back as rotate_from_sha256. Returned
		// here and nowhere else: the ports are already in this response, and
		// a digest of three ports is not a secret on its own.
		"sequence_sha256": sshguard.KnockSequenceDigest(state.Sequence.Ports),
	}
	if len(state.Sequence.PreviousPorts) > 0 && !state.Confirmed {
		out["previous_ports"] = state.Sequence.PreviousPorts
	}
	writeJSON(w, http.StatusOK, out)
}
