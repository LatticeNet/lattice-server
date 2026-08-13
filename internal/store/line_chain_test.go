package store

import (
	"errors"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestLineChainPlanAndReserveUseExactGraphRevision(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	attempt := LineChainAttempt{
		ApprovalID: "approval-b-a", Operation: LineChainOperationSet,
		SourceLineUUID: "line-b", CandidateTargetLineUUID: "line-a", RequestSHA256: "request-b-a",
	}
	planned, deduped, err := store.PlanLineChain(attempt)
	if err != nil || deduped || planned.PlanGraphRevision != 0 || planned.Status != LineChainStatusPlanned {
		t.Fatalf("plan = %+v deduped=%v err=%v", planned, deduped, err)
	}
	reserved, err := store.ReserveLineChain(attempt.ApprovalID, 0)
	if err != nil || reserved.QueuedGraphRevision != 1 || reserved.Status != LineChainStatusApplying {
		t.Fatalf("reserve = %+v err=%v", reserved, err)
	}
	snapshot := store.LineChainSnapshot()
	if snapshot.Revision != 1 {
		t.Fatalf("revision=%d, want 1", snapshot.Revision)
	}
	if _, err := store.ReserveLineChain(attempt.ApprovalID, 0); !errors.Is(err, ErrLineChainRevisionConflict) {
		t.Fatalf("stale reserve error=%v", err)
	}
}

func TestLineChainPlanDeduplicatesExactRequestAndSerializesSource(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	attempt := LineChainAttempt{
		ApprovalID: "approval-1", Operation: LineChainOperationSet,
		SourceLineUUID: "line-b", CandidateTargetLineUUID: "line-a", RequestSHA256: "same",
	}
	first, _, err := store.PlanLineChain(attempt)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := attempt
	duplicate.ApprovalID = "approval-2"
	got, deduped, err := store.PlanLineChain(duplicate)
	if err != nil || !deduped || got.ApprovalID != first.ApprovalID {
		t.Fatalf("dedupe = %+v deduped=%v err=%v", got, deduped, err)
	}
	different := duplicate
	different.RequestSHA256 = "different"
	if _, _, err := store.PlanLineChain(different); !errors.Is(err, ErrLineChainSourceBusy) {
		t.Fatalf("different concurrent plan error=%v", err)
	}
}

func TestLineChainReserveRejectsTwoNodeCycleWithoutRevisionMutation(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	first := LineChainAttempt{ApprovalID: "b-a", Operation: LineChainOperationSet, SourceLineUUID: "b", CandidateTargetLineUUID: "a", RequestSHA256: "b-a"}
	if _, _, err := store.PlanLineChain(first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveLineChain(first.ApprovalID, 0); err != nil {
		t.Fatal(err)
	}
	second := LineChainAttempt{ApprovalID: "a-b", Operation: LineChainOperationSet, SourceLineUUID: "a", CandidateTargetLineUUID: "b", RequestSHA256: "a-b", PlanGraphRevision: 1}
	planned, _, err := store.PlanLineChain(second)
	if err != nil || planned.PlanGraphRevision != 1 {
		t.Fatalf("second plan=%+v err=%v", planned, err)
	}
	if _, err := store.ReserveLineChain(second.ApprovalID, 1); !errors.Is(err, ErrLineChainCycle) {
		t.Fatalf("cycle reserve error=%v", err)
	}
	snapshot := store.LineChainSnapshot()
	if snapshot.Revision != 1 || snapshot.Attempts[second.ApprovalID].Status != LineChainStatusPlanned {
		t.Fatalf("cycle failure mutated state: %+v", snapshot)
	}
}

func TestApproveLineChainQueuesTaskAndReservesRevisionAtomically(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	approval := model.Approval{ID: "approval-1", NodeID: "node-a", Plugin: "singbox-linechain", Service: "network/lines",
		Method: "chain_set_apply", Action: "apply-line-chain:digest", ArtifactDigest: "digest", RequestSHA256: "request", Plan: "{}", Status: model.ApprovalPending, CreatedAt: now}
	attempt := LineChainAttempt{ApprovalID: approval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source", SourceNodeID: "node-a",
		CandidateTargetLineUUID: "target", CandidateArtifactSHA256: "digest", RequestSHA256: "request", PlanGraphRevision: 0}
	if _, _, err := s.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatal(err)
	}
	approved := approval
	approved.Status = model.ApprovalApproved
	approved.ApprovedBy = "admin"
	task := model.Task{ID: "task-1", ApprovalID: approval.ID, Targets: []string{"node-a"}, Script: "apply", Status: model.TaskQueued}
	reserved, committed, err := s.ApproveLineChain(approved, task)
	if err != nil || !committed {
		t.Fatalf("approve line chain: reserved=%+v committed=%v err=%v", reserved, committed, err)
	}
	snapshot := s.LineChainSnapshot()
	if snapshot.Revision != 1 || snapshot.Attempts[approval.ID].Status != LineChainStatusApplying || snapshot.Attempts[approval.ID].QueuedGraphRevision != 1 {
		t.Fatalf("reservation not atomic: %+v", snapshot)
	}
	storedApproval, ok := s.Approval(approval.ID)
	if !ok || storedApproval.Status != model.ApprovalApproved {
		t.Fatalf("approval not committed: %+v ok=%v", storedApproval, ok)
	}
	storedTask, ok := s.Task(task.ID)
	if !ok || storedTask.ApprovalID != approval.ID || len(s.Tasks()) != 1 {
		t.Fatalf("task not committed exactly once: %+v ok=%v all=%+v", storedTask, ok, s.Tasks())
	}
	if _, _, err := s.ApproveLineChain(approved, task); !errors.Is(err, ErrTaskTransitionConflict) {
		t.Fatalf("reapproval minted second task: %v", err)
	}
	blocked, err := s.LeaseTaskDeliveriesWithDurableProtocols("node-a", 1, false, false)
	if err != nil || len(blocked) != 0 {
		t.Fatalf("capability downgrade exposed linechain task: deliveries=%+v err=%v", blocked, err)
	}
	validator := func(LineChainCompileStateSnapshot, model.Approval, LineChainAttempt, model.Task) error { return nil }
	deliveries, err := s.LeaseTaskDeliveriesWithLineChainValidator("node-a", 1, false, true, validator)
	if err != nil || len(deliveries) != 1 || deliveries[0].DurableProtocol != DurableProtocolLineChainV1 || !deliveries[0].DurableResult {
		t.Fatalf("linechain durable lease mismatch: deliveries=%+v err=%v", deliveries, err)
	}
	leased := s.LineChainSnapshot().Attempts[approval.ID]
	if leased.FirstLeaseGraphRevision != 1 || leased.IssuedTaskID != task.ID || leased.IssuedLeaseID != deliveries[0].Task.LeaseID || leased.IssuedScriptSHA256 == "" || leased.IssuedArtifactSHA256 != approval.ArtifactDigest || s.LineChainSnapshot().Revision != 1 {
		t.Fatalf("first lease changed revision or missed L: %+v", leased)
	}
	redelivered, err := s.LeaseTaskDeliveriesWithLineChainValidator("node-a", 1, false, true, validator)
	if err != nil || len(redelivered) != 1 || redelivered[0].Task.LeaseID != deliveries[0].Task.LeaseID || s.LineChainSnapshot().Revision != 1 {
		t.Fatalf("same lease was not redelivered: first=%+v second=%+v err=%v", deliveries, redelivered, err)
	}
	s.mu.Lock()
	mutated := s.state.Tasks[task.ID]
	mutated.Script = "mutated-after-lease"
	s.state.Tasks[task.ID] = mutated
	s.mu.Unlock()
	afterMutation, err := s.LeaseTaskDeliveriesWithLineChainValidator("node-a", 1, false, true, validator)
	if !errors.Is(err, ErrTaskTransitionConflict) || len(afterMutation) != 0 {
		t.Fatalf("mutated issued task reused lease: deliveries=%+v err=%v", afterMutation, err)
	}
	staleApproval, _ := s.Approval(approval.ID)
	staleTask, _ := s.Task(task.ID)
	issuedAfter := s.LineChainSnapshot().Attempts[approval.ID]
	if staleApproval.Status != model.ApprovalApproved || staleTask.Status != model.TaskLeased || s.LineChainSnapshot().Revision != 1 || issuedAfter.IssuedLeaseID != leased.IssuedLeaseID {
		t.Fatalf("post-lease corruption mutated frozen authority: approval=%+v task=%+v snapshot=%+v", staleApproval, staleTask, s.LineChainSnapshot())
	}
}

func TestLineChainFirstLeaseValidationFailureReleasesReservationAtomically(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{ID: "approval-stale", NodeID: "node-a", Plugin: "singbox-linechain", Service: "network/lines",
		Method: "chain_set_apply", Action: "apply-line-chain:digest", ArtifactDigest: "digest", RequestSHA256: "request", Plan: "{}", Status: model.ApprovalPending}
	attempt := LineChainAttempt{ApprovalID: approval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source", SourceNodeID: "node-a",
		CandidateTargetLineUUID: "target", CandidateArtifactSHA256: "digest", RequestSHA256: "request", PlanGraphRevision: 0}
	if _, _, err := s.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatal(err)
	}
	approved := approval
	approved.Status = model.ApprovalApproved
	task := model.Task{ID: "task-stale", ApprovalID: approval.ID, Targets: []string{"node-a"}, Script: "stale", Status: model.TaskQueued}
	if _, committed, err := s.ApproveLineChain(approved, task); err != nil || !committed {
		t.Fatalf("approve: committed=%v err=%v", committed, err)
	}
	deliveries, err := s.LeaseTaskDeliveriesWithLineChainValidator("node-a", 1, false, true,
		func(LineChainCompileStateSnapshot, model.Approval, LineChainAttempt, model.Task) error {
			return errors.New("credential changed")
		})
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("stale task was delivered: %+v err=%v", deliveries, err)
	}
	gotApproval, _ := s.Approval(approval.ID)
	gotTask, _ := s.Task(task.ID)
	snapshot := s.LineChainSnapshot()
	gotAttempt := snapshot.Attempts[approval.ID]
	if gotApproval.Status != model.ApprovalRejected || !gotApproval.Stale || gotApproval.StaleCode != "line_chain_inputs_changed" ||
		gotTask.Status != model.TaskCancelled || gotAttempt.Status != LineChainStatusFailed || snapshot.Revision != 2 {
		t.Fatalf("stale release not atomic: approval=%+v task=%+v attempt=%+v revision=%d", gotApproval, gotTask, gotAttempt, snapshot.Revision)
	}
}
