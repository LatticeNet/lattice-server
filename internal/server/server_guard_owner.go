package server

import (
	"fmt"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// lattice_guard ownership between decision and execution (KI-29). The
// store classifies the writers (store.GuardWriteOf) and re-checks the owner
// when a task is leased; the refusals here stop the decisions that would
// put an apply of one side behind an unfinished apply of the other. They
// read and then act in separate lock sections, so two decisions racing each
// other can both pass; the lease recheck, which holds the store lock, is
// what makes the outcome correct anyway.

// guardWriterNoun names a writer for a sentence.
func guardWriterNoun(kind string) string {
	switch kind {
	case store.GuardWriterNetGuard:
		return "NetGuard plan"
	case store.GuardWriterBeacon:
		return "beacon plan with NetGuard rules"
	case store.GuardWriterSelfDNS:
		return "self-host DNS plan with a firewall ruleset"
	}
	return "legacy firewall plan"
}

// guardWriterInFlightRefusal refuses a decision for a writer of one side
// while an apply of the other side on the node has not finished, naming
// that apply and what to do. netGuardSide is the side of the decision.
func (s *Server) guardWriterInFlightRefusal(nodeID string, netGuardSide bool, what string) error {
	for _, other := range s.store.GuardWritersInFlight(nodeID) {
		if other.NetGuardSide() == netGuardSide {
			continue
		}
		state := "is queued"
		if other.Leased {
			state = "is running"
		}
		return fmt.Errorf("%s: a %s for this node (approval %s) %s and has not reported a result, and each apply replaces the whole lattice_guard table; wait for it to finish, or cancel its task, then try again",
			what, guardWriterNoun(other.Kind), other.ApprovalID, state)
	}
	return nil
}

// groupCoverageRefusal refuses a writer that rebuilds lattice_guard outside
// NetGuard on a node NetGuard does not manage but covers through a node
// group whose security groups it applies (design 32 D7 with S4). Callers
// test a managed binding first, with their own sentence. A covered node
// NetGuard does not manage can use neither route until it is adopted.
// The group is named only to a caller who may read node groups.
func (s *Server) groupCoverageRefusal(p principal, nodeID string) error {
	managed, viaGroup := s.store.NetGuardCoverage(nodeID)
	if managed || viaGroup == "" {
		return nil
	}
	group := "a node group"
	if rbac.Allows(p.Principal, "group:read", "") {
		group = fmt.Sprintf("node group %q", viaGroup)
	}
	return fmt.Errorf("node is in %s whose security groups NetGuard applies, so its firewall is NetGuard's to write; adopt the node in NetGuard, or take it out of the group, before planning its firewall outside NetGuard", group)
}

// auditGuardSupersessions records the applies the last lease superseded.
func (s *Server) auditGuardSupersessions() {
	for _, sup := range s.store.TakeGuardSupersessions() {
		s.recordAudit(model.AuditEvent{
			ID: id.New("audit"), At: sup.At, ActorID: sup.ActorID, TokenID: sup.TokenID, NodeID: sup.NodeID,
			Action: "network.guard.superseded", Scope: "network:apply", Decision: "deny", Reason: sup.Reason,
			Metadata: map[string]string{"approval_id": sup.ApprovalID, "task_id": sup.TaskID, "writer": sup.Kind},
		})
	}
}
