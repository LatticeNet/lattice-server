package server

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/sshguard"
)

// The SSH Guard status view: one row per node, driven by what the node
// reports rather than by how its last approval ended.
//
// The board used to derive a node's state from its approvals alone, so an
// arm that applied and then reverted because nobody confirmed inside the
// window read as a red "reverted", and an arm rejected weeks earlier read as
// a red "arm failed". On the fleet that produced this, every one of those
// nodes had password authentication off and the operator's key installed:
// secure by the only measure that matters, and coloured as a failure by a
// record of what the control plane had once tried. This view separates the
// two. Posture is the node's own sshd facts and decides the row; the arm and
// confirm history is carried alongside as history.

// sshGuardStage is where a node sits in the arm/confirm sequence, as the
// control plane can tell from its approvals and, past the window, from the
// node's own report.
type sshGuardStage string

const (
	// Nothing has been planned for this node.
	sshGuardStageIdle sshGuardStage = "idle"
	// An arm plan is waiting for a decision.
	sshGuardStageArmPending sshGuardStage = "arm_pending"
	// Approved, not yet applied on the node.
	sshGuardStageArmApproved sshGuardStage = "arm_approved"
	// The newest arm was rejected, dismissed, or failed to apply.
	sshGuardStageArmFailed sshGuardStage = "arm_failed"
	// Applied with the revert timer running and no confirm filed yet.
	sshGuardStageAwaitingConfirm sshGuardStage = "awaiting_confirm"
	// A confirm plan is waiting for a decision; the timer is still running.
	sshGuardStageConfirmPending sshGuardStage = "confirm_pending"
	// Confirm approved, not yet applied; the timer is still running.
	sshGuardStageConfirmApproved sshGuardStage = "confirm_approved"
	// Confirm applied: the change is permanent.
	sshGuardStageConfirmed sshGuardStage = "confirmed"
	// A durable hardening-only arm applied. There was no timer and there is
	// no confirm to file; the change is permanent.
	sshGuardStageHardened sshGuardStage = "hardened"
	// The window closed with no confirm applied and the node's report does
	// not show the change: the timer undid it.
	sshGuardStageReverted sshGuardStage = "reverted"
	// The window closed with no confirm applied, yet a report collected after
	// the deadline still shows the gate. The change is on the node whatever
	// the records say; it was confirmed by hand, or the timer never fired.
	sshGuardStageInForce sshGuardStage = "in_force"
)

// sshGuardTimerArmedMark is written into a durable arm's approval when the
// host's own key check failed and the script armed the timer after all. The
// approval is still applied; the mark is how the view knows a confirm is
// owed on a node whose plan said none would be.
const sshGuardTimerArmedMark = "revert timer armed after all: no authorized key was found on the host"

// sshGuardApprovalRef is the history the row carries about one approval.
type sshGuardApprovalRef struct {
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
	// Outcome folds status and the dismissal reason into one word the
	// console can key on: pending, approved, applied, rejected, dismissed,
	// superseded.
	Outcome   string    `json:"outcome"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Arm only.
	Durable          bool `json:"durable,omitempty"`
	GatesFirewall    bool `json:"gates_firewall,omitempty"`
	Knock            bool `json:"knock,omitempty"`
	ConfirmWindowSec int  `json:"confirm_window_sec,omitempty"`
}

// sshGuardSSHDView is the node's reported sshd configuration, verbatim, so
// the console can show the evidence behind the posture rather than only the
// verdict.
type sshGuardSSHDView struct {
	PasswordAuthentication bool      `json:"password_authentication"`
	PubkeyAuthentication   bool      `json:"pubkey_authentication"`
	PermitRootLogin        string    `json:"permit_root_login"`
	Ports                  []int     `json:"ports,omitempty"`
	ObservedAt             time.Time `json:"observed_at"`
}

// sshGuardKnockView is the non-secret half of the knock state, inlined so the
// board does not need a second call per row.
type sshGuardKnockView struct {
	Knowledge      string `json:"knowledge"`
	Revealable     bool   `json:"revealable"`
	RequiresStepUp bool   `json:"requires_step_up"`
	Interactive    bool   `json:"interactive_only"`
	Note           string `json:"note"`
	ApprovalID     string `json:"approval_id,omitempty"`
	Confirmed      *bool  `json:"confirmed,omitempty"`
}

type sshGuardNodeStatus struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name,omitempty"`
	Enrolled bool   `json:"enrolled"`

	// Posture decides the row. It is derived from SSHD, never from the
	// approvals below.
	Posture sshguard.SSHPosture `json:"posture"`
	SSHD    *sshGuardSSHDView   `json:"sshd,omitempty"`
	// SSHDNote is the agent's reason for reporting no facts, when it gave one.
	SSHDNote           string     `json:"sshd_note,omitempty"`
	RealityCollectedAt *time.Time `json:"reality_collected_at,omitempty"`

	// KnockGate is true when the node's report lists the inet lattice_knock
	// table: the gate is on the node right now, whoever put it there.
	KnockGate bool `json:"knock_gate"`

	// Stage and its qualifiers. StageIsHistory says the stage is a record of
	// a past attempt on a node that is secured anyway, so the row shows it
	// as history rather than as its state.
	Stage                sshGuardStage `json:"stage"`
	StageIsHistory       bool          `json:"stage_is_history"`
	RevertArmed          bool          `json:"revert_armed"`
	RevertDeadline       *time.Time    `json:"revert_deadline,omitempty"`
	ActionableApprovalID string        `json:"actionable_approval_id,omitempty"`

	LastArm     *sshGuardApprovalRef `json:"last_arm,omitempty"`
	LastConfirm *sshGuardApprovalRef `json:"last_confirm,omitempty"`

	Knock sshGuardKnockView `json:"knock"`
}

// sshGuardFacts maps the model's sshd report onto the derivation's input.
func sshGuardFacts(reality *model.GuardNodeReality) *sshguard.SSHDFacts {
	if reality == nil || reality.SSHD == nil {
		return nil
	}
	return &sshguard.SSHDFacts{
		PasswordAuthentication: reality.SSHD.PasswordAuthentication,
		PubkeyAuthentication:   reality.SSHD.PubkeyAuthentication,
		PermitRootLogin:        reality.SSHD.PermitRootLogin,
	}
}

// sshGuardPostureFor derives the node's posture from its last reality report.
func (s *Server) sshGuardPostureFor(nodeID string) sshguard.SSHPosture {
	return sshguard.DerivePosture(sshGuardFacts(s.guardRealityForLint(nodeID)))
}

// sshGuardKnockGate reports whether the node's reality lists the knock table.
// The agent names foreign tables "family name", so this is an exact match on
// the table SSH Guard installs and nothing else.
func sshGuardKnockGate(reality *model.GuardNodeReality) bool {
	if reality == nil {
		return false
	}
	want := "inet " + sshguard.KnockTable
	for _, table := range reality.ForeignTables {
		if strings.TrimSpace(table) == want {
			return true
		}
	}
	return false
}

func sshGuardApprovalOutcome(a model.Approval) string {
	switch {
	case a.Status == model.ApprovalApplied:
		return "applied"
	case a.Status == model.ApprovalPending:
		return "pending"
	case a.Status == model.ApprovalApproved:
		return "approved"
	case sshGuardApprovalSuperseded(a):
		return "superseded"
	case a.Status == approvalStatusDismissed:
		return "dismissed"
	default:
		return "rejected"
	}
}

func sshGuardApprovalRefFor(a model.Approval) *sshGuardApprovalRef {
	out := &sshGuardApprovalRef{
		ApprovalID: a.ID, Status: a.Status, Outcome: sshGuardApprovalOutcome(a),
		Reason: a.Reason, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
	if a.Action == sshGuardArmAction {
		if art, err := sshguard.ParseApprovalPlan(a.Plan); err == nil {
			out.Durable = art.Durable
			out.GatesFirewall = strings.TrimSpace(art.KnockNFT) != ""
			out.Knock = strings.TrimSpace(art.KnockdConf) != ""
			out.ConfirmWindowSec = art.ConfirmWindowSec
		}
	}
	return out
}

// sshGuardNewest picks the newest approval by authoring time. CreatedAt is
// the one timestamp that means the same thing on every record; UpdatedAt on
// a dismissed record is the day of the cleanup.
func sshGuardNewest(list []model.Approval) (model.Approval, bool) {
	if len(list) == 0 {
		return model.Approval{}, false
	}
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		}
		return list[i].ID > list[j].ID
	})
	return list[0], true
}

// sshGuardNodeStatusFor builds one row.
func (s *Server) sshGuardNodeStatusFor(nodeID string, now time.Time) sshGuardNodeStatus {
	reality := s.guardRealityForLint(nodeID)
	out := sshGuardNodeStatus{
		NodeID:    nodeID,
		Enrolled:  s.resolveNodeCapability(nodeID, sshGuardPlugin).Allowed,
		Posture:   sshguard.DerivePosture(sshGuardFacts(reality)),
		KnockGate: sshGuardKnockGate(reality),
		Stage:     sshGuardStageIdle,
	}
	if node, ok := s.store.Node(nodeID); ok {
		out.NodeName = node.Name
	}
	if reality != nil {
		collected := reality.CollectedAt.UTC()
		out.RealityCollectedAt = &collected
		out.SSHDNote = reality.SSHDNote
		if reality.SSHD != nil {
			out.SSHD = &sshGuardSSHDView{
				PasswordAuthentication: reality.SSHD.PasswordAuthentication,
				PubkeyAuthentication:   reality.SSHD.PubkeyAuthentication,
				PermitRootLogin:        reality.SSHD.PermitRootLogin,
				Ports:                  append([]int(nil), reality.SSHD.Ports...),
				ObservedAt:             reality.SSHD.ObservedAt.UTC(),
			}
		}
	}

	// Knock knowledge, inlined.
	ks := s.sshGuardKnockStateFor(nodeID)
	out.Knock = sshGuardKnockView{
		Knowledge:      string(ks.Knowledge),
		Revealable:     knockRevealable(ks.Knowledge),
		RequiresStepUp: true,
		Interactive:    true,
		Note:           knockStateNoteWithGate(ks, out.KnockGate),
		ApprovalID:     ks.ApprovalID,
	}
	if ks.Knowledge == knockInstalled || ks.Knowledge == knockInstalledSuperseded {
		confirmed := ks.Confirmed
		out.Knock.Confirmed = &confirmed
	}

	// Stage from the approvals.
	var arms, confirms []model.Approval
	for _, a := range s.store.Approvals() {
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
	arm, ok := sshGuardNewest(arms)
	if !ok {
		out.StageIsHistory = out.Posture.State == sshguard.PostureSecured
		return out
	}
	out.LastArm = sshGuardApprovalRefFor(arm)
	switch arm.Status {
	case model.ApprovalPending:
		out.Stage = sshGuardStageArmPending
		out.ActionableApprovalID = arm.ID
		return out
	case model.ApprovalApproved:
		out.Stage = sshGuardStageArmApproved
		out.ActionableApprovalID = arm.ID
		return out
	case model.ApprovalApplied:
	default:
		// Rejected, dismissed, or superseded. A superseded arm with a confirm
		// dispatched after it did reach the node (see sshGuardKnockStateFor);
		// the rest never did or were undone.
		if sshGuardApprovalSuperseded(arm) {
			if c, ok := sshGuardNewest(sshGuardConfirmsAfter(confirms, arm)); ok && (c.Status == model.ApprovalApplied || sshGuardApprovalSuperseded(c)) {
				out.LastConfirm = sshGuardApprovalRefFor(c)
				out.Stage = sshGuardStageConfirmed
				return out
			}
		}
		out.Stage = sshGuardStageArmFailed
		out.StageIsHistory = out.Posture.State == sshguard.PostureSecured
		return out
	}

	// Applied. A durable arm has no timer unless the host said otherwise.
	if out.LastArm.Durable && !strings.Contains(arm.Reason, sshGuardTimerArmedMark) {
		out.Stage = sshGuardStageHardened
		return out
	}
	current, hasConfirm := sshGuardNewest(sshGuardConfirmsAfter(confirms, arm))
	if hasConfirm {
		out.LastConfirm = sshGuardApprovalRefFor(current)
		switch current.Status {
		case model.ApprovalPending:
			out.Stage = sshGuardStageConfirmPending
			out.ActionableApprovalID = current.ID
			out.RevertArmed = true
		case model.ApprovalApproved:
			out.Stage = sshGuardStageConfirmApproved
			out.ActionableApprovalID = current.ID
			out.RevertArmed = true
		case model.ApprovalApplied:
			out.Stage = sshGuardStageConfirmed
			return out
		default:
			if sshGuardApprovalSuperseded(current) {
				out.Stage = sshGuardStageConfirmed
				return out
			}
			out.Stage = sshGuardStageAwaitingConfirm
			out.RevertArmed = true
		}
	} else {
		out.Stage = sshGuardStageAwaitingConfirm
		out.RevertArmed = true
	}

	// The timer is a deadline. The approval's UpdatedAt is when the apply
	// was recorded, which is after the timer started, so this deadline is the
	// latest it can be. Past it the records still say "applied, no confirm";
	// the node does not.
	window := out.LastArm.ConfirmWindowSec
	if window == 0 {
		window = sshguard.DefaultConfirmWindowSec
	}
	deadline := arm.UpdatedAt.UTC().Add(time.Duration(window) * time.Second)
	out.RevertDeadline = &deadline
	if now.Before(deadline) {
		return out
	}
	out.RevertArmed = false
	out.RevertDeadline = nil
	out.ActionableApprovalID = ""
	if out.LastArm.GatesFirewall && out.KnockGate && reality != nil && !reality.CollectedAt.Before(deadline) {
		out.Stage = sshGuardStageInForce
		return out
	}
	out.Stage = sshGuardStageReverted
	out.StageIsHistory = out.Posture.State == sshguard.PostureSecured
	return out
}

// sshGuardConfirmsAfter is the confirms authored after one arm; a confirm
// that predates the arm belongs to an earlier attempt and says nothing about
// this one.
func sshGuardConfirmsAfter(confirms []model.Approval, arm model.Approval) []model.Approval {
	out := make([]model.Approval, 0, len(confirms))
	for _, c := range confirms {
		if c.CreatedAt.After(arm.CreatedAt) {
			out = append(out, c)
		}
	}
	return out
}

// knockStateNoteWithGate adds what the node itself says to the sentence the
// approvals produce. The one case that changes is an applied, unconfirmed
// arm: the approvals cannot tell whether its timer removed the gate, and the
// node's report can.
func knockStateNoteWithGate(state sshGuardKnockState, gatePresent bool) string {
	note := knockStateNote(state)
	if state.ParseError != "" || !gatePresent {
		return note
	}
	if state.Knowledge == knockInstalled && !state.Confirmed {
		return "The control plane knows the knock sequence from the arm that was applied. That arm was never confirmed, but the node's latest report shows the lattice_knock table in place, so the gate is still up and this is the sequence that opens it."
	}
	return note
}

// handleSSHGuardStatus serves the rows. One node when node_id is given,
// otherwise every node the principal may read. Scope is the pair the knock
// state already requires, per node.
func (s *Server) handleSSHGuardStatus(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID  string   `json:"node_id"`
		NodeIDs []string `json:"node_ids"`
	}
	if r.Method == http.MethodPost && !decodeClientJSON(w, r, &req) {
		return
	}
	if r.Method == http.MethodGet {
		req.NodeID = strings.TrimSpace(r.URL.Query().Get("node_id"))
	}
	now := time.Now().UTC()
	if id := strings.TrimSpace(req.NodeID); id != "" {
		if !s.sshGuardKnockScopes(w, p, id) {
			return
		}
		if _, ok := s.store.Node(id); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		row := s.sshGuardNodeStatusFor(id, now)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node": row, "nodes": []sshGuardNodeStatus{row}})
		return
	}
	requested := req.NodeIDs
	ids := s.visibleNodeIDs(p, "sshguard:read", requested)
	rows := make([]sshGuardNodeStatus, 0, len(ids))
	for _, id := range ids {
		if !rbac.Allows(p.Principal, "network:plan", id) {
			continue
		}
		if _, ok := s.store.Node(id); !ok {
			continue
		}
		rows = append(rows, s.sshGuardNodeStatusFor(id, now))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].NodeID < rows[j].NodeID })
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": rows})
}
