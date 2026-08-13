package store

import (
	"errors"
	"testing"
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
