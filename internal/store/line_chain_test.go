package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func TestRejectLineChainApprovalStaleUsesAtomicPersistenceBoundary(t *testing.T) {
	setup := func(t *testing.T) *Store {
		s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
		if err != nil {
			t.Fatal(err)
		}
		approval := model.Approval{ID: "approval-stale-plan", Status: model.ApprovalPending}
		attempt := LineChainAttempt{ApprovalID: approval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source", CandidateTargetLineUUID: "target", RequestSHA256: "request"}
		if _, _, err := s.PlanLineChainApproval(attempt, approval); err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("pre_rename", func(t *testing.T) {
		s := setup(t)
		if err := os.Mkdir(s.path+".tmp", 0o700); err != nil {
			t.Fatal(err)
		}
		if committed, err := s.RejectLineChainApprovalStale("approval-stale-plan", "line_chain_inputs_changed", "fresh plan required"); committed || err == nil {
			t.Fatalf("reject committed=%v err=%v", committed, err)
		}
		approval, _ := s.Approval("approval-stale-plan")
		if approval.Status != model.ApprovalPending || s.LineChainSnapshot().Attempts[approval.ID].Status != LineChainStatusPlanned || s.LineChainSnapshot().Revision != 0 {
			t.Fatalf("pre-rename stale transition published: approval=%+v snapshot=%+v", approval, s.LineChainSnapshot())
		}
		if committed, err := s.RejectLineChainApprovalStale("approval-stale-plan", "line_chain_inputs_changed", "fresh plan required"); !committed || err != nil {
			t.Fatalf("retry committed=%v err=%v", committed, err)
		}
	})
	t.Run("post_rename", func(t *testing.T) {
		s := setup(t)
		s.syncParentDir = func(string) error { return errors.New("forced post-rename sync failure") }
		if committed, err := s.RejectLineChainApprovalStale("approval-stale-plan", "line_chain_inputs_changed", "fresh plan required"); !committed || err == nil {
			t.Fatalf("reject committed=%v err=%v", committed, err)
		}
		approval, _ := s.Approval("approval-stale-plan")
		attempt := s.LineChainSnapshot().Attempts[approval.ID]
		if approval.Status != model.ApprovalRejected || !approval.Stale || attempt.Status != LineChainStatusFailed || s.LineChainSnapshot().Revision != 0 {
			t.Fatalf("post-rename stale transition not published: approval=%+v attempt=%+v", approval, attempt)
		}
	})
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

func TestLineChainReserveRejectsThreeNodeCycleAtExactCASRevision(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	edges := []LineChainAttempt{
		{ApprovalID: "a-b", Operation: LineChainOperationSet, SourceLineUUID: "a", CandidateTargetLineUUID: "b", RequestSHA256: "a-b", PlanGraphRevision: 0},
		{ApprovalID: "b-c", Operation: LineChainOperationSet, SourceLineUUID: "b", CandidateTargetLineUUID: "c", RequestSHA256: "b-c", PlanGraphRevision: 1},
		{ApprovalID: "c-a", Operation: LineChainOperationSet, SourceLineUUID: "c", CandidateTargetLineUUID: "a", RequestSHA256: "c-a", PlanGraphRevision: 2},
	}
	for i, edge := range edges {
		if _, _, err := s.PlanLineChain(edge); err != nil {
			t.Fatalf("plan edge %d: %v", i, err)
		}
		_, err := s.ReserveLineChain(edge.ApprovalID, uint64(i))
		if i < 2 && err != nil {
			t.Fatalf("reserve edge %d: %v", i, err)
		}
		if i == 2 && !errors.Is(err, ErrLineChainCycle) {
			t.Fatalf("closing three-node cycle error=%v", err)
		}
	}
	snapshot := s.LineChainSnapshot()
	if snapshot.Revision != 2 || snapshot.Attempts["c-a"].Status != LineChainStatusPlanned {
		t.Fatalf("cycle CAS mutated revision/candidate: %+v", snapshot)
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
	if err != nil || len(deliveries) != 1 || deliveries[0].DurableProtocol != DurableProtocolLineChainV2 || !deliveries[0].DurableResult {
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

func TestCompleteLineChainTaskResultPromotesFrozenCandidateAndReplaysExactly(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{ID: "approval-result", NodeID: "node-a", Plugin: "singbox-linechain", PluginVersion: "1", Service: "network/lines", Method: "chain_set_apply",
		Action: "apply-line-chain:digest", ArtifactDigest: "digest", RequestSHA256: "request", Plan: "{}", Status: model.ApprovalPending, Targets: []string{"node-a"}}
	frozen := LineChainDefinition{SourceLineUUID: "source", SourceNodeID: "node-a", SourceLineHashID: "hash-source", SourceInboundTag: "in-source",
		TargetLineUUID: "target", TargetNodeID: "node-b", TargetDefinitionDigest: "definition", TargetPublicMaterialDigest: "public",
		TargetCredentialDigest: "credential", OutboundTag: "out", FragmentPath: "lattice-linechain-a.json", FragmentSHA256: "fragment", SidecarPatchSHA256: "sidecar", ArtifactSHA256: "digest"}
	attempt := LineChainAttempt{ApprovalID: approval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source", SourceNodeID: "node-a",
		CandidateTargetLineUUID: "target", CandidateArtifactSHA256: "digest", CandidateDefinition: frozen, RequestSHA256: "request", PlanGraphRevision: 0}
	if _, _, err := s.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatal(err)
	}
	approved := approval
	approved.Status = model.ApprovalApproved
	task := model.Task{ID: "task-result", ApprovalID: approval.ID, Targets: []string{"node-a"}, Script: "exact-script", Status: model.TaskQueued}
	if _, committed, err := s.ApproveLineChain(approved, task); err != nil || !committed {
		t.Fatalf("approve committed=%v err=%v", committed, err)
	}
	validator := func(LineChainCompileStateSnapshot, model.Approval, LineChainAttempt, model.Task) error { return nil }
	deliveries, err := s.LeaseTaskDeliveriesWithLineChainValidator("node-a", 1, false, true, validator)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("lease=%+v err=%v", deliveries, err)
	}
	result := model.TaskResult{TaskID: task.ID, NodeID: "node-a", LeaseID: deliveries[0].Task.LeaseID, ExitCode: 0, FinishedAt: time.Now().UTC()}
	if committed, err := s.CompleteLineChainTaskResult(result, approved, LineChainStatusDrifted, "target_missing", ""); err != nil || !committed {
		t.Fatalf("complete committed=%v err=%v", committed, err)
	}
	definition := s.LineChainSnapshot().Definitions["source"]
	if definition.ApprovalID != approval.ID || definition.TargetCredentialDigest != "credential" || definition.Status != LineChainStatusDrifted || definition.DriftCode != "target_missing" || definition.Generation != 1 || len(s.LineChainSnapshot().Attempts) != 0 || s.LineChainSnapshot().Revision != 2 {
		t.Fatalf("frozen promotion mismatch: %+v snapshot=%+v", definition, s.LineChainSnapshot())
	}
	if matches, found, err := s.ConfirmTaskResultReplay(result); err != nil || !found || !matches {
		t.Fatalf("lost-ACK replay matches=%v found=%v err=%v", matches, found, err)
	}
	conflict := result
	conflict.ExitCode = 1
	if matches, found, _ := s.ConfirmTaskResultReplay(conflict); !found || matches {
		t.Fatalf("conflicting replay accepted: matches=%v found=%v", matches, found)
	}
}

func TestCompleteLineChainTaskResultFailurePreservesBaselineAndFreshPlanSupersedes(t *testing.T) {
	s, approval, task, leaseID := seedLineChainResultAttempt(t)
	baseline := LineChainDefinition{SourceLineUUID: "source", SourceNodeID: "node-a", TargetLineUUID: "old-target", ArtifactSHA256: "old", Generation: 4, Status: LineChainStatusConverged}
	s.state.LineChainDefinitions["source"] = baseline
	attempt := s.state.LineChainAttempts[approval.ID]
	attempt.BaseGeneration, attempt.BaseArtifactSHA256 = 4, "old"
	s.state.LineChainAttempts[approval.ID] = attempt
	result := model.TaskResult{TaskID: task.ID, NodeID: "node-a", LeaseID: leaseID, ExitCode: 1, Error: "host failed", FinishedAt: time.Now().UTC()}
	if committed, err := s.CompleteLineChainTaskResult(result, approval, LineChainStatusAppliedUnobserved, "host_apply_failed", "host failed"); err != nil || !committed {
		t.Fatalf("complete committed=%v err=%v", committed, err)
	}
	gotApproval, _ := s.Approval(approval.ID)
	snapshot := s.LineChainSnapshot()
	if gotApproval.Status != model.ApprovalApproved || gotApproval.Reason != "execution failed; fresh plan required" || !reflect.DeepEqual(snapshot.Definitions["source"], baseline) || snapshot.Attempts[approval.ID].Status != LineChainStatusFailed || snapshot.Revision != 2 {
		t.Fatalf("failed result changed baseline or authority: approval=%+v snapshot=%+v", gotApproval, snapshot)
	}
	newApproval := model.Approval{ID: "approval-fresh", NodeID: "node-a", Plugin: "singbox-linechain", Service: "network/lines", Method: "chain_set_apply", Action: "apply-line-chain:new", ArtifactDigest: "new", RequestSHA256: "fresh", Status: model.ApprovalPending}
	newAttempt := LineChainAttempt{ApprovalID: newApproval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source", SourceNodeID: "node-a", CandidateTargetLineUUID: "new-target", BaseGeneration: 4, BaseArtifactSHA256: "old", CandidateArtifactSHA256: "new", RequestSHA256: "fresh", PlanGraphRevision: 2}
	if _, _, err := s.PlanLineChainApproval(newAttempt, newApproval); err != nil {
		t.Fatal(err)
	}
	if _, exists := s.LineChainSnapshot().Attempts[approval.ID]; exists {
		t.Fatal("fresh plan retained an unordered failed attempt for the same source")
	}
}

func TestCompleteLineChainTaskResultPostRenameReplayConfirmsDurability(t *testing.T) {
	s, approval, task, leaseID := seedLineChainResultAttempt(t)
	calls := 0
	s.syncParentDir = func(string) error {
		calls++
		if calls == 1 {
			return errors.New("forced directory sync failure")
		}
		return nil
	}
	result := model.TaskResult{TaskID: task.ID, NodeID: "node-a", LeaseID: leaseID, ExitCode: 0, FinishedAt: time.Now().UTC()}
	if committed, err := s.CompleteLineChainTaskResult(result, approval, LineChainStatusAppliedUnobserved, "", ""); !committed || err == nil {
		t.Fatalf("post-rename result committed=%v err=%v", committed, err)
	}
	if matches, found, err := s.ConfirmTaskResultReplay(result); err != nil || !found || !matches {
		t.Fatalf("exact retry did not reconfirm durability: matches=%v found=%v err=%v", matches, found, err)
	}
}

func seedLineChainResultAttempt(t *testing.T) (*Store, model.Approval, model.Task, string) {
	t.Helper()
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{ID: "approval-result-helper", NodeID: "node-a", Plugin: "singbox-linechain", PluginVersion: "1", Service: "network/lines", Method: "chain_set_apply", Action: "apply-line-chain:digest", ArtifactDigest: "digest", RequestSHA256: "request", Plan: "{}", Status: model.ApprovalPending, Targets: []string{"node-a"}}
	frozen := LineChainDefinition{SourceLineUUID: "source", SourceNodeID: "node-a", SourceLineHashID: "hash", SourceInboundTag: "in", TargetLineUUID: "target", TargetNodeID: "node-b", ArtifactSHA256: "digest"}
	attempt := LineChainAttempt{ApprovalID: approval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source", SourceNodeID: "node-a", CandidateTargetLineUUID: "target", CandidateArtifactSHA256: "digest", CandidateDefinition: frozen, RequestSHA256: "request"}
	if _, _, err := s.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	task := model.Task{ID: "task-result-helper", ApprovalID: approval.ID, Targets: []string{"node-a"}, Script: "script", Status: model.TaskQueued}
	if _, committed, err := s.ApproveLineChain(approval, task); err != nil || !committed {
		t.Fatalf("approve committed=%v err=%v", committed, err)
	}
	deliveries, err := s.LeaseTaskDeliveriesWithLineChainValidator("node-a", 1, false, true, func(LineChainCompileStateSnapshot, model.Approval, LineChainAttempt, model.Task) error { return nil })
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("lease=%+v err=%v", deliveries, err)
	}
	return s, approval, task, deliveries[0].Task.LeaseID
}

func TestReconcileLineChainsUsesExactObservedSetAndRemoveEvidence(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	s.state.LineChainDefinitions["set-ok"] = LineChainDefinition{SourceLineUUID: "set-ok", TargetLineUUID: "target", OutboundTag: "out", Status: LineChainStatusAppliedUnobserved}
	s.state.LineChainDefinitions["set-bad"] = LineChainDefinition{SourceLineUUID: "set-bad", TargetLineUUID: "target", OutboundTag: "out", Status: LineChainStatusAppliedUnobserved}
	s.state.LineChainDefinitions["remove-ok"] = LineChainDefinition{SourceLineUUID: "remove-ok", OutboundTag: "old-out", Status: LineChainStatusAppliedUnobserved}
	s.state.LineChainDefinitions["remove-bad"] = LineChainDefinition{SourceLineUUID: "remove-bad", OutboundTag: "old-out", Status: LineChainStatusAppliedUnobserved}
	s.state.LineChainGraphRevision = 7
	committed, err := s.ReconcileLineChains(map[string]LineChainObservation{
		"set-ok":     {OutboundTag: "out", DownstreamLineUUID: "target"},
		"set-bad":    {OutboundTag: "wrong", DownstreamLineUUID: "target"},
		"remove-ok":  {},
		"remove-bad": {OutboundTag: "old-out"},
	})
	if err != nil || !committed {
		t.Fatalf("reconcile committed=%v err=%v", committed, err)
	}
	snapshot := s.LineChainSnapshot()
	if snapshot.Definitions["set-ok"].Status != LineChainStatusConverged || snapshot.Definitions["set-bad"].DriftCode != "observed_mismatch" ||
		snapshot.Definitions["remove-ok"].Status != LineChainStatusConverged || snapshot.Definitions["remove-ok"].TargetLineUUID != "" ||
		snapshot.Definitions["remove-bad"].DriftCode != "remove_artifacts_present" || snapshot.Revision != 7 || len(s.Tasks()) != 0 {
		t.Fatalf("unexpected reconciliation: %+v", snapshot)
	}
}

func TestAppendAuditIdempotentRepairsDurabilityWithoutDuplicates(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.syncParentDir = func(string) error {
		calls++
		if calls == 1 {
			return errors.New("forced sync failure")
		}
		return nil
	}
	event := model.AuditEvent{ID: "audit_linechain_exact", At: time.Unix(1_700_000_000, 0).UTC(), Action: "linechain.apply", Decision: "allow"}
	if committed, err := s.AppendAuditIdempotent(event); !committed || err == nil {
		t.Fatalf("first append committed=%v err=%v", committed, err)
	}
	if committed, err := s.AppendAuditIdempotent(event); committed || err != nil {
		t.Fatalf("retry committed=%v err=%v", committed, err)
	}
	if events := s.AuditEvents(); len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("audit retry duplicated evidence: %+v", events)
	}
}

func TestLineChainTransitionAuditEvidenceSurvivesRuntimeHotRestartBeforeSink(t *testing.T) {
	dir := t.TempDir()
	statePath, hotPath := filepath.Join(dir, "state.json"), filepath.Join(dir, "runtime.db")
	cipher := testCipher(t)
	open := func() *Store {
		s, err := OpenWithCipher(statePath, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	event := func(id, action string, at time.Time) model.AuditEvent {
		return model.AuditEvent{ID: id, At: at, Action: action, Decision: "allow"}
	}
	approval := model.Approval{ID: "approval-hot-evidence", NodeID: "node-a", Plugin: "singbox-linechain", PluginVersion: "1", Service: "network/lines",
		Method: "chain_set_apply", Action: "apply-line-chain:digest", ArtifactDigest: "digest", RequestSHA256: "request", Plan: "{}", Status: model.ApprovalPending, Targets: []string{"node-a"}}
	attempt := LineChainAttempt{ApprovalID: approval.ID, Operation: LineChainOperationSet, SourceLineUUID: "source", SourceNodeID: "node-a",
		CandidateTargetLineUUID: "target", CandidateArtifactSHA256: "digest", CandidateDefinition: LineChainDefinition{SourceLineUUID: "source", SourceNodeID: "node-a", TargetLineUUID: "target", TargetNodeID: "node-b", OutboundTag: "out", ArtifactSHA256: "digest"}, RequestSHA256: "request"}
	s := open()
	planAudit := event("audit-plan-hot", "linechain.plan", now)
	if _, _, err := s.PlanLineChainApproval(attempt, approval, planAudit); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	if got, ok := s.AuditEventByID(planAudit.ID); !ok || !reflect.DeepEqual(got, planAudit) {
		t.Fatalf("plan evidence missing after sinkless restart: %+v ok=%v", got, ok)
	}
	approval.Status = model.ApprovalApproved
	task := model.Task{ID: "task-hot-evidence", ApprovalID: approval.ID, Targets: []string{"node-a"}, Script: "script", Status: model.TaskQueued}
	approveAudit := event("audit-approve-hot", "linechain.approve", now.Add(time.Second))
	if _, committed, err := s.ApproveLineChain(approval, task, approveAudit); err != nil || !committed {
		t.Fatalf("approve committed=%v err=%v", committed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	if got, ok := s.AuditEventByID(approveAudit.ID); !ok || !reflect.DeepEqual(got, approveAudit) {
		t.Fatalf("approve evidence missing after sinkless restart: %+v ok=%v", got, ok)
	}
	deliveries, err := s.LeaseTaskDeliveriesWithLineChainValidator("node-a", 1, false, true, func(LineChainCompileStateSnapshot, model.Approval, LineChainAttempt, model.Task) error { return nil })
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("lease=%+v err=%v", deliveries, err)
	}
	result := model.TaskResult{TaskID: task.ID, NodeID: "node-a", LeaseID: deliveries[0].Task.LeaseID, FinishedAt: now.Add(2 * time.Second)}
	terminalAudit := event("audit-terminal-hot", "linechain.apply", result.FinishedAt)
	if committed, err := s.CompleteLineChainTaskResult(result, approval, LineChainStatusAppliedUnobserved, "", "", terminalAudit); err != nil || !committed {
		t.Fatalf("terminal committed=%v err=%v", committed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	if got, ok := s.AuditEventByID(terminalAudit.ID); !ok || !reflect.DeepEqual(got, terminalAudit) {
		t.Fatalf("terminal evidence missing after sinkless restart: %+v ok=%v", got, ok)
	}
	driftAudit := event("audit-reconcile-drift-hot", "linechain.drift", now.Add(3*time.Second))
	driftAudit.Decision, driftAudit.Reason = "deny", "observed_mismatch"
	if committed, err := s.ReconcileLineChainsWithAudits(map[string]LineChainObservation{"source": {OutboundTag: "wrong", DownstreamLineUUID: "target"}}, func(definition LineChainDefinition) (model.AuditEvent, bool) {
		driftAudit.At = definition.UpdatedAt
		return driftAudit, true
	}); err != nil || !committed {
		t.Fatalf("drift reconcile committed=%v err=%v", committed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	if got, ok := s.AuditEventByID(driftAudit.ID); !ok || !reflect.DeepEqual(got, driftAudit) {
		t.Fatalf("drift reconciliation evidence missing after sinkless restart: %+v ok=%v", got, ok)
	}
	convergedAudit := event("audit-reconcile-converged-hot", "linechain.apply", now.Add(4*time.Second))
	if committed, err := s.ReconcileLineChainsWithAudits(map[string]LineChainObservation{"source": {OutboundTag: "out", DownstreamLineUUID: "target"}}, func(definition LineChainDefinition) (model.AuditEvent, bool) {
		convergedAudit.At = definition.UpdatedAt
		return convergedAudit, true
	}); err != nil || !committed {
		t.Fatalf("converged reconcile committed=%v err=%v", committed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	defer s.Close()
	if got, ok := s.AuditEventByID(convergedAudit.ID); !ok || !reflect.DeepEqual(got, convergedAudit) {
		t.Fatalf("converged reconciliation evidence missing after sinkless restart: %+v ok=%v", got, ok)
	}
}
