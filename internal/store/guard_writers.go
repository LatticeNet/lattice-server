package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/selfdns"
)

// Writers of lattice_guard (design 32 D7, KI-29). NetGuard is the only
// writer on a node it covers, but an apply is decided and executed at
// different times: a legacy firewall or self-host DNS plan approved while
// the node was unmanaged can reach the agent after NetGuard adopted it, and
// each apply replaces the whole table. The server refuses the decisions
// that would interleave the two sides; the lease below re-checks the owner
// under the store lock, as the task is handed out, so a stale apply is
// superseded with a sentence instead of run.

const (
	GuardWriterNetGuard       = "netguard"
	GuardWriterBeacon         = "beacon"
	GuardWriterSelfDNS        = "selfdns"
	GuardWriterLegacyFirewall = "legacy_firewall"

	// NetGuardApplyAction is the action of NetGuard's own approvals.
	NetGuardApplyAction = "apply-ruleset:netguard-v1"

	// ApprovalStaleGuardOwnerChanged marks an approval the lease superseded
	// because lattice_guard changed owner after it was approved.
	ApprovalStaleGuardOwnerChanged = "guard_owner_changed"
)

// GuardWrite is how an approval's apply rebuilds lattice_guard.
type GuardWrite struct {
	Kind string
	// Ruleset is the table the apply writes. It is empty for a self-host DNS
	// plan whose text no longer parses: such a plan still counts as a legacy
	// writer, so it is refused rather than run.
	Ruleset string
}

// NetGuardSide is true for the writers whose ruleset NetGuard compiled.
func (w GuardWrite) NetGuardSide() bool {
	return w.Kind == GuardWriterNetGuard || w.Kind == GuardWriterBeacon
}

// GuardWriteOf says whether approval's apply rebuilds lattice_guard, and as
// which writer: NetGuard's own plan, a beacon plan carrying a NetGuard
// companion, any other nft plan (the legacy firewall route), or a self-host
// DNS plan that carries a ruleset.
func GuardWriteOf(a model.Approval) (GuardWrite, bool) {
	switch a.Plugin {
	case "nft":
		if a.Action == NetGuardApplyAction {
			return GuardWrite{Kind: GuardWriterNetGuard, Ruleset: a.Plan}, true
		}
		return GuardWrite{Kind: GuardWriterLegacyFirewall, Ruleset: a.Plan}, true
	case "selfdns":
		artifacts, err := selfdns.ParseApprovalPlan(a.Plan)
		if err != nil {
			return GuardWrite{Kind: GuardWriterSelfDNS}, true
		}
		if artifacts.NFTRuleset == "" {
			return GuardWrite{}, false
		}
		return GuardWrite{Kind: GuardWriterSelfDNS, Ruleset: artifacts.NFTRuleset}, true
	case model.BeaconApprovalPlugin:
		if a.Action != model.BeaconPlanKind {
			return GuardWrite{}, false
		}
		var plan model.BeaconPlan
		if err := json.Unmarshal([]byte(a.Plan), &plan); err != nil || plan.Kind != model.BeaconPlanKind || plan.NodeID != a.NodeID || plan.NetGuard == nil {
			return GuardWrite{}, false
		}
		return GuardWrite{Kind: GuardWriterBeacon, Ruleset: plan.NetGuard.Ruleset}, true
	}
	return GuardWrite{}, false
}

// GuardWriterTask is an approved guard-writing apply that still owes its
// result on a node.
type GuardWriterTask struct {
	ApprovalID string
	TaskID     string
	Kind       string
	// Leased is true while an agent holds a live lease: it may be running.
	Leased bool
}

// NetGuardSide is GuardWrite.NetGuardSide for the task's writer.
func (t GuardWriterTask) NetGuardSide() bool { return GuardWrite{Kind: t.Kind}.NetGuardSide() }

// GuardWritersInFlight lists, oldest first, the approved guard-writing tasks
// on nodeID that have not finished: queued, or leased with no result, and
// not past the queue deadline.
func (s *Store) GuardWritersInFlight(nodeID string) []GuardWriterTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.guardWritersInFlightLocked(s.state, nodeID, time.Now().UTC())
}

func (s *Store) guardWritersInFlightLocked(st State, nodeID string, now time.Time) []GuardWriterTask {
	var tasks []model.Task
	for _, t := range st.Tasks {
		if t.ApprovalID != "" && taskTargetAwaitingResult(t, nodeID, st.Results, st.TaskResultReceipts, st.TaskTargetStates, now, s.taskQueueDeadline) {
			tasks = append(tasks, t)
		}
	}
	sort.Slice(tasks, func(i, j int) bool {
		if !tasks[i].CreatedAt.Equal(tasks[j].CreatedAt) {
			return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
		}
		return tasks[i].ID < tasks[j].ID
	})
	var out []GuardWriterTask
	for _, t := range tasks {
		a, ok := st.Approvals[t.ApprovalID]
		if !ok || a.NodeID != nodeID || a.Status != model.ApprovalApproved {
			continue
		}
		w, ok := GuardWriteOf(a)
		if !ok {
			continue
		}
		leased := false
		if start, ok := taskTargetLeaseStart(t, nodeID); ok {
			leased = !taskLeaseExpiredAt(start, t.TimeoutSec, now)
		}
		out = append(out, GuardWriterTask{ApprovalID: a.ID, TaskID: t.ID, Kind: w.Kind, Leased: leased})
	}
	return out
}

// guardOwnerAtLeaseLocked re-checks lattice_guard's owner as t is about to
// be leased to nodeID. supersede, when set, is the sentence the approval is
// rejected with: a legacy writer on a node NetGuard now covers, or a beacon
// companion on a node NetGuard no longer manages. hold is true while a
// writer of the other side is leased on the node and may be running: the
// task waits for the next poll instead of racing it.
func (s *Store) guardOwnerAtLeaseLocked(st State, t model.Task, nodeID string, now time.Time) (supersede string, hold bool) {
	a, ok := st.Approvals[t.ApprovalID]
	if t.ApprovalID == "" || !ok {
		return "", false
	}
	w, ok := GuardWriteOf(a)
	if !ok {
		return "", false
	}
	managed, viaGroup := s.netGuardCoverageLocked(st, nodeID)
	switch {
	case !w.NetGuardSide() && managed:
		return "NetGuard took over this node's firewall after this plan was approved, and it is the only writer of lattice_guard there, so the task was not run; plan the change in NetGuard", false
	case !w.NetGuardSide() && viaGroup != "":
		return fmt.Sprintf("this node is in node group %q, whose security groups NetGuard applies, so this plan, approved before that, was not run; adopt the node in NetGuard or take it out of the group, then plan again", viaGroup), false
	case w.Kind == GuardWriterBeacon && !managed:
		return "NetGuard no longer manages this node, so the beacon plan's NetGuard rules were not applied; plan the beacon again", false
	}
	for _, other := range s.guardWritersInFlightLocked(st, nodeID, now) {
		if other.TaskID != t.ID && other.Leased && other.NetGuardSide() != w.NetGuardSide() {
			return "", true
		}
	}
	return "", false
}

// GuardSupersession is one apply the lease superseded, kept until the
// server records it in the audit log.
type GuardSupersession struct {
	NodeID     string
	ApprovalID string
	TaskID     string
	Kind       string
	Reason     string
	ActorID    string
	TokenID    string
	At         time.Time
}

// TakeGuardSupersessions returns and forgets the supersessions recorded
// since the last call. They live in memory only: the approval's stale code
// and reason are the durable record, the audit line is the loud one.
func (s *Store) TakeGuardSupersessions() []GuardSupersession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.guardSuperseded
	s.guardSuperseded = nil
	return out
}
