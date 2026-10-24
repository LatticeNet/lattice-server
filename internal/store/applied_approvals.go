package store

import (
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// AppliedApproval is an approval whose plan reached its node, and when.
type AppliedApproval struct {
	Approval  model.Approval
	AppliedAt time.Time
}

// NodeAppliedApprovals returns the approvals of the given plugins on one node
// whose plan reached the node, newest first by the time it did. Two records
// say a plan reached its node: a plugin that tracks the outcome marks the
// approval applied (NetGuard, outbound policy, self-host DNS, beacon, SSH
// Guard), and a plugin that does not (the legacy firewall route) leaves it
// approved with an apply task that finished. A rejected approval never
// counts, even when its task finished: the result handlers reject an apply
// that landed on stale intent.
//
// It reads the approval and task tables under one lock and writes nothing.
func (s *Store) NodeAppliedApprovals(nodeID string, plugins ...string) []AppliedApproval {
	want := make(map[string]bool, len(plugins))
	for _, plugin := range plugins {
		want[plugin] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	approved := map[string]model.Approval{}
	var out []AppliedApproval
	for _, a := range s.state.Approvals {
		if a.NodeID != nodeID || !want[a.Plugin] {
			continue
		}
		switch a.Status {
		case model.ApprovalApplied:
			at := a.UpdatedAt
			if at.IsZero() {
				at = a.CreatedAt
			}
			out = append(out, AppliedApproval{Approval: a, AppliedAt: at})
		case model.ApprovalApproved:
			approved[a.ID] = a
		}
	}
	if len(approved) > 0 {
		finished := map[string]time.Time{}
		for _, t := range s.state.Tasks {
			if _, ok := approved[t.ApprovalID]; !ok || t.Status != model.TaskFinished {
				continue
			}
			if t.FinishedAt.After(finished[t.ApprovalID]) {
				finished[t.ApprovalID] = t.FinishedAt
			}
		}
		for approvalID, at := range finished {
			out = append(out, AppliedApproval{Approval: approved[approvalID], AppliedAt: at})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].AppliedAt.Equal(out[j].AppliedAt) {
			return out[i].AppliedAt.After(out[j].AppliedAt)
		}
		return out[i].Approval.ID > out[j].Approval.ID
	})
	return out
}

// PersistCallsForTest counts the authoritative state writes this store has
// attempted. A test reads it before and after a call to prove the call wrote
// nothing.
func (s *Store) PersistCallsForTest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.testPersistCalls
}
