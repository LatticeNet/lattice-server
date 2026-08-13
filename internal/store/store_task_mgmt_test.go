package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestApproveNetGuardRejectsDependencyChangeAtomically(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-queue", Name: "queue"})
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		ID: "approval-queue", NodeID: "n1", Plugin: "nft", Action: "apply-ruleset:netguard-v1",
		Status: model.ApprovalPending, Plan: "table inet lattice_guard {}",
	}
	if err := s.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(approval.Plan)))
	if _, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{
		NodeID: "n1", Managed: true, GroupIDs: []string{group.ID}, LastPlanSHA: planSHA,
	}); err != nil {
		t.Fatal(err)
	}

	group.Name = "changed before atomic queue"
	if _, err := s.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	approved := approval
	approved.Status = model.ApprovalApproved
	committed, err := s.ApproveNetGuard(approved, nil)
	if committed || !errors.Is(err, ErrGuardVersionConflict) {
		t.Fatalf("stale approve-only decision committed=%v err=%v", committed, err)
	}
	task := model.Task{
		ID: "task-queue", ApprovalID: approval.ID, Targets: []string{"n1"}, Status: model.TaskQueued,
	}
	committed, err = s.ApproveNetGuard(approved, &task)
	if committed || !errors.Is(err, ErrGuardVersionConflict) {
		t.Fatalf("stale approval queued committed=%v err=%v", committed, err)
	}
	stored, _ := s.Approval(approval.ID)
	if stored.Status != model.ApprovalPending || len(s.Tasks()) != 0 {
		t.Fatalf("failed atomic queue partially transitioned approval/task: approval=%+v tasks=%+v", stored, s.Tasks())
	}
}

func TestGuardCompileInputsDoNotAliasStoreMemory(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	groupInput := model.SecurityGroup{ID: "sg-clone", Rules: []model.GuardRule{{
		ID: "rule", Ports: []model.GuardPortRange{{From: 22, To: 22}},
	}}}
	if _, err := s.UpsertSecurityGroup(groupInput); err != nil {
		t.Fatal(err)
	}
	zoneInput := model.GuardZone{ID: "zone-clone", Interfaces: []string{"eth0"}, CIDRs: []string{"10.0.0.0/8"}}
	if err := s.UpsertGuardZone(zoneInput); err != nil {
		t.Fatal(err)
	}
	bindingInput := model.NodeGuardBinding{
		NodeID: "n1", GroupIDs: []string{"sg-clone"}, ZoneIDs: []string{"zone-clone"},
		Overrides: []model.GuardRule{{ID: "override", Ports: []model.GuardPortRange{{From: 443, To: 443}}}},
	}
	if _, err := s.UpsertNodeGuardBinding(bindingInput); err != nil {
		t.Fatal(err)
	}
	nftInput := model.NFTInputs{NodeID: "n1", PublicTCP: []int{22}}
	if err := s.UpsertNFTInputs(nftInput); err != nil {
		t.Fatal(err)
	}

	groupInput.Rules[0].Ports[0].From = 1
	zoneInput.Interfaces[0], zoneInput.CIDRs[0] = "bad0", "192.0.2.0/24"
	bindingInput.GroupIDs[0], bindingInput.ZoneIDs[0], bindingInput.Overrides[0].Ports[0].From = "bad", "bad", 1
	nftInput.PublicTCP[0] = 1
	group, _ := s.SecurityGroup("sg-clone")
	zone, _ := s.GuardZone("zone-clone")
	binding, _ := s.NodeGuardBinding("n1")
	nft, _ := s.NFTInputs("n1")
	if group.Rules[0].Ports[0].From != 22 || zone.Interfaces[0] != "eth0" || zone.CIDRs[0] != "10.0.0.0/8" ||
		binding.GroupIDs[0] != "sg-clone" || binding.ZoneIDs[0] != "zone-clone" || binding.Overrides[0].Ports[0].From != 443 ||
		nft.PublicTCP[0] != 22 {
		t.Fatalf("write input aliases store: group=%+v zone=%+v binding=%+v nft=%+v", group, zone, binding, nft)
	}

	group.Rules[0].Ports[0].From = 2
	zone.Interfaces[0], zone.CIDRs[0] = "bad1", "198.51.100.0/24"
	binding.GroupIDs[0], binding.ZoneIDs[0], binding.Overrides[0].Ports[0].From = "bad", "bad", 2
	nft.PublicTCP[0] = 2
	groupAgain, _ := s.SecurityGroup("sg-clone")
	zoneAgain, _ := s.GuardZone("zone-clone")
	bindingAgain, _ := s.NodeGuardBinding("n1")
	nftAgain, _ := s.NFTInputs("n1")
	if groupAgain.Rules[0].Ports[0].From != 22 || zoneAgain.Interfaces[0] != "eth0" || zoneAgain.CIDRs[0] != "10.0.0.0/8" ||
		bindingAgain.GroupIDs[0] != "sg-clone" || bindingAgain.ZoneIDs[0] != "zone-clone" || bindingAgain.Overrides[0].Ports[0].From != 443 ||
		nftAgain.PublicTCP[0] != 22 {
		t.Fatalf("read result aliases store: group=%+v zone=%+v binding=%+v nft=%+v", groupAgain, zoneAgain, bindingAgain, nftAgain)
	}
}

func TestLeaseTasksPersistenceFailureDoesNotPublishLiveLease(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(statePath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTask(model.Task{ID: "task-lease-save", Targets: []string{"n1"}, Status: model.TaskQueued}); err != nil {
		t.Fatal(err)
	}
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(blockedParent, "state.json")
	leased, err := s.LeaseTasks("n1", 1)
	if err == nil || len(leased) != 0 {
		t.Fatalf("LeaseTasks() = %+v, %v; want pre-commit failure", leased, err)
	}
	stored, _ := s.Task("task-lease-save")
	if stored.Status != model.TaskQueued || stored.LeaseID != "" || len(stored.TargetLeases) != 0 {
		t.Fatalf("pre-commit lease failure polluted live state: %+v", stored)
	}
}

func TestLeaseTasksReturnsCommittedLeaseOnPostRenameSyncFailure(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTask(model.Task{ID: "task-lease-sync", Targets: []string{"n1"}, Status: model.TaskQueued}); err != nil {
		t.Fatal(err)
	}
	s.syncParentDir = func(string) error { return errors.New("forced post-rename sync failure") }
	leased, err := s.LeaseTasks("n1", 1)
	if err != nil || len(leased) != 1 || leased[0].LeaseID == "" {
		t.Fatalf("LeaseTasks() = %+v, %v; want committed lease", leased, err)
	}
	stored, _ := s.Task("task-lease-sync")
	if stored.Status != model.TaskLeased || !taskLeaseMatches(stored, "n1", leased[0].LeaseID) {
		t.Fatalf("committed lease not published: %+v", stored)
	}
	if !errors.Is(s.ReadyCheck(), errStoreDurabilityDegraded) {
		t.Fatalf("post-rename lease sync failure did not degrade readiness: %v", s.ReadyCheck())
	}
}

func TestGuardPlanInvalidatesOnMetricsAndNFTCompileInputChanges(t *testing.T) {
	t.Run("referenced node heartbeat address", func(t *testing.T) {
		s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertNode(model.Node{ID: "peer", PublicIP: "192.0.2.10"}); err != nil {
			t.Fatal(err)
		}
		group, err := s.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-peer", Rules: []model.GuardRule{{
			ID: "peer", Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "peer"},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		before, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{
			NodeID: "n1", GroupIDs: []string{group.ID}, LastPlanSHA: "planned",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateMetrics("peer", model.Metrics{}, "", "192.0.2.10", "", "", "", "", model.HostFacts{}); err != nil {
			t.Fatal(err)
		}
		unchanged, _ := s.NodeGuardBinding("n1")
		if unchanged.LastPlanSHA != before.LastPlanSHA || unchanged.Version != before.Version {
			t.Fatalf("unchanged heartbeat address invalidated plan: before=%+v after=%+v", before, unchanged)
		}
		if err := s.UpdateMetrics("peer", model.Metrics{}, "", "198.51.100.10", "", "", "", "", model.HostFacts{}); err != nil {
			t.Fatal(err)
		}
		after, _ := s.NodeGuardBinding("n1")
		if after.LastPlanSHA != "" || after.Version <= before.Version || !strings.Contains(after.LastError, "dependency changed") {
			t.Fatalf("heartbeat address change did not invalidate plan: before=%+v after=%+v", before, after)
		}
	})

	t.Run("target nft zone baseline", func(t *testing.T) {
		s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertNFTInputs(model.NFTInputs{NodeID: "n1", InterfaceName: "eth0"}); err != nil {
			t.Fatal(err)
		}
		before, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", LastPlanSHA: "planned"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertNFTInputs(model.NFTInputs{NodeID: "n1", InterfaceName: "ens3"}); err != nil {
			t.Fatal(err)
		}
		after, _ := s.NodeGuardBinding("n1")
		if after.LastPlanSHA != "" || after.Version <= before.Version || !strings.Contains(after.LastError, "dependency changed") {
			t.Fatalf("nft baseline change did not invalidate plan: before=%+v after=%+v", before, after)
		}
	})
}

// TestCancelTask verifies only queued tasks are cancelable and the sentinel
// errors are returned for leased and missing tasks.
func TestCancelTask(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.CreateTask(model.Task{ID: "task-q", Targets: []string{"n1"}, Status: model.TaskQueued}); err != nil {
		t.Fatalf("create queued: %v", err)
	}
	if err := s.CreateTask(model.Task{ID: "task-l", Targets: []string{"n1"}, Status: model.TaskLeased}); err != nil {
		t.Fatalf("create leased: %v", err)
	}

	got, err := s.CancelTask("task-q")
	if err != nil {
		t.Fatalf("cancel queued: %v", err)
	}
	if got.Status != model.TaskCancelled {
		t.Fatalf("status = %q want cancelled", got.Status)
	}
	if got.FinishedAt.IsZero() {
		t.Fatalf("FinishedAt not stamped on cancel")
	}

	if _, err := s.CancelTask("task-l"); !errors.Is(err, ErrTaskNotCancelable) {
		t.Fatalf("cancel leased err = %v want ErrTaskNotCancelable", err)
	}
	if _, err := s.CancelTask("missing"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("cancel missing err = %v want ErrTaskNotFound", err)
	}
}

// TestDeleteTask verifies a task and only its own results are removed, and that
// deleting a missing task returns ErrTaskNotFound.
func TestDeleteTask(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.CreateTask(model.Task{ID: "task-del", Targets: []string{"n1"}, Status: model.TaskFinished}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "task-del", NodeID: "n1"}); err != nil {
		t.Fatalf("add result: %v", err)
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "other", NodeID: "n1"}); err != nil {
		t.Fatalf("add other result: %v", err)
	}

	if err := s.DeleteTask("task-del"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.Task("task-del"); ok {
		t.Fatalf("task still present after delete")
	}
	foundOther := false
	for _, r := range s.Results() {
		if r.TaskID == "task-del" {
			t.Fatalf("result for deleted task not pruned")
		}
		if r.TaskID == "other" {
			foundOther = true
		}
	}
	if !foundOther {
		t.Fatalf("unrelated result wrongly pruned")
	}

	if err := s.DeleteTask("missing"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("delete missing err = %v want ErrTaskNotFound", err)
	}
}

func TestTaskFanoutLeasesEveryTargetAndAggregatesStatus(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.CreateTask(model.Task{ID: "task-fan", Targets: []string{"n1", "n2"}, Status: model.TaskQueued}); err != nil {
		t.Fatalf("create: %v", err)
	}

	n1, err := s.LeaseTasks("n1", 3)
	if err != nil {
		t.Fatalf("lease n1: %v", err)
	}
	n2, err := s.LeaseTasks("n2", 3)
	if err != nil {
		t.Fatalf("lease n2: %v", err)
	}
	if len(n1) != 1 || len(n2) != 1 {
		t.Fatalf("fanout leases: n1=%d n2=%d want 1 each", len(n1), len(n2))
	}
	if n1[0].LeaseID == "" || n2[0].LeaseID == "" || n1[0].LeaseID == n2[0].LeaseID {
		t.Fatalf("per-node leases not distinct: n1=%q n2=%q", n1[0].LeaseID, n2[0].LeaseID)
	}
	if dup, err := s.LeaseTasks("n1", 3); err != nil || len(dup) != 0 {
		t.Fatalf("duplicate lease n1 got len=%d err=%v", len(dup), err)
	}

	now := time.Now().UTC()
	if err := s.AddTaskResult(model.TaskResult{TaskID: "task-fan", NodeID: "n1", LeaseID: n1[0].LeaseID, ExitCode: 2, FinishedAt: now}); err != nil {
		t.Fatalf("add n1 result: %v", err)
	}
	if task, ok := s.Task("task-fan"); !ok || task.Status != model.TaskLeased || !task.FinishedAt.IsZero() {
		t.Fatalf("partial status: ok=%v status=%q finished=%v", ok, task.Status, task.FinishedAt)
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "task-fan", NodeID: "n2", LeaseID: n2[0].LeaseID, ExitCode: 0, FinishedAt: now.Add(time.Second)}); err != nil {
		t.Fatalf("add n2 result: %v", err)
	}
	if task, ok := s.Task("task-fan"); !ok || task.Status != model.TaskFailed || task.FinishedAt.IsZero() {
		t.Fatalf("final status: ok=%v status=%q finished=%v", ok, task.Status, task.FinishedAt)
	}
}

func TestCompleteNetGuardTaskResultRejectsConcurrentBindingVersionWithoutPartialCommit(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		ID: "approval-netguard", NodeID: "n1", Plugin: "nft", Action: "apply-ruleset:netguard-v1",
		Status: model.ApprovalApproved, Plan: "table inet lattice_guard {}",
	}
	if err := s.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	binding, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTask(model.Task{
		ID: "task-netguard", ApprovalID: approval.ID, Targets: []string{"n1"}, Status: model.TaskQueued,
	}); err != nil {
		t.Fatal(err)
	}
	leased, err := s.LeaseTasks("n1", 1)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: tasks=%+v err=%v", leased, err)
	}

	concurrent := binding
	concurrent.LastError = "intent changed"
	if _, err := s.UpsertNodeGuardBinding(concurrent); err != nil {
		t.Fatal(err)
	}
	binding.AppliedTableSHA = strings.Repeat("a", 64)
	approval.Status = model.ApprovalApplied
	committed, err := s.CompleteNetGuardTaskResult(model.TaskResult{
		TaskID: leased[0].ID, NodeID: "n1", LeaseID: leased[0].LeaseID, ExitCode: 0,
	}, approval, binding)
	if committed || !errors.Is(err, ErrGuardVersionConflict) {
		t.Fatalf("stale transition committed=%v err=%v", committed, err)
	}
	if got := s.Results(); len(got) != 0 {
		t.Fatalf("stale transition stored a result: %+v", got)
	}
	storedTask, _ := s.Task(leased[0].ID)
	if storedTask.Status != model.TaskLeased {
		t.Fatalf("stale transition made task terminal: %+v", storedTask)
	}
	storedApproval, _ := s.Approval(approval.ID)
	if storedApproval.Status != model.ApprovalApproved {
		t.Fatalf("stale transition updated approval: %+v", storedApproval)
	}
	storedBinding, _ := s.NodeGuardBinding("n1")
	if storedBinding.LastError != "intent changed" || storedBinding.AppliedTableSHA != "" {
		t.Fatalf("stale transition overwrote concurrent binding: %+v", storedBinding)
	}
}

func TestCompleteNetGuardTaskResultRejectsConcurrentDependencyChangeWithoutPartialCommit(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-a", Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		ID: "approval-netguard-dependency", NodeID: "n1", Plugin: "nft", Action: "apply-ruleset:netguard-v1",
		Status: model.ApprovalApproved, Plan: "table inet lattice_guard {}",
	}
	if err := s.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	binding, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{
		NodeID: "n1", Managed: true, GroupIDs: []string{group.ID},
		LastPlanSHA: "reviewed-plan-anchor",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTask(model.Task{
		ID: "task-netguard-dependency", ApprovalID: approval.ID, Targets: []string{"n1"}, Status: model.TaskQueued,
	}); err != nil {
		t.Fatal(err)
	}
	leased, err := s.LeaseTasks("n1", 1)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: tasks=%+v err=%v", leased, err)
	}

	// Simulate a group mutation after the server compiled current intent but
	// before CompleteNetGuardTaskResult obtains the store lock. The group update
	// atomically invalidates the plan anchor and advances the binding revision.
	group.Name = "changed after compile"
	if _, err := s.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApplied
	binding.AppliedTableSHA = strings.Repeat("a", 64)
	committed, err := s.CompleteNetGuardTaskResult(model.TaskResult{
		TaskID: leased[0].ID, NodeID: "n1", LeaseID: leased[0].LeaseID, ExitCode: 0,
	}, approval, binding)
	if committed || !errors.Is(err, ErrGuardVersionConflict) {
		t.Fatalf("dependency-stale transition committed=%v err=%v", committed, err)
	}
	if got := s.Results(); len(got) != 0 {
		t.Fatalf("dependency-stale transition stored a result: %+v", got)
	}
	storedTask, _ := s.Task(leased[0].ID)
	if storedTask.Status != model.TaskLeased {
		t.Fatalf("dependency-stale transition made task terminal: %+v", storedTask)
	}
	storedApproval, _ := s.Approval(approval.ID)
	if storedApproval.Status != model.ApprovalApproved {
		t.Fatalf("dependency-stale transition updated approval: %+v", storedApproval)
	}
	storedBinding, _ := s.NodeGuardBinding("n1")
	if storedBinding.LastPlanSHA != "" || storedBinding.Version <= binding.Version ||
		!strings.Contains(storedBinding.LastError, "dependency changed") || storedBinding.AppliedTableSHA != "" {
		t.Fatalf("dependency invalidation was lost: before=%+v after=%+v", binding, storedBinding)
	}
}

func TestCompleteNetGuardTaskResultPublishesCommittedStateOnPostRenameSyncFailure(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		ID: "approval-netguard-sync", NodeID: "n1", Plugin: "nft", Action: "apply-ruleset:netguard-v1",
		Status: model.ApprovalApproved, Plan: "table inet lattice_guard {}",
	}
	if err := s.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	binding, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTask(model.Task{ID: "task-netguard-sync", ApprovalID: approval.ID, Targets: []string{"n1"}}); err != nil {
		t.Fatal(err)
	}
	leased, err := s.LeaseTasks("n1", 1)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: tasks=%+v err=%v", leased, err)
	}
	approval.Status = model.ApprovalApplied
	binding.AppliedTableSHA = strings.Repeat("a", 64)
	s.syncParentDir = func(string) error { return errors.New("forced post-rename sync failure") }
	committed, err := s.CompleteNetGuardTaskResult(model.TaskResult{
		TaskID: leased[0].ID, NodeID: "n1", LeaseID: leased[0].LeaseID, ExitCode: 0,
	}, approval, binding)
	if !committed || err == nil || !strings.Contains(err.Error(), "forced post-rename sync failure") {
		t.Fatalf("post-rename outcome committed=%v err=%v", committed, err)
	}
	if len(s.Results()) != 1 {
		t.Fatalf("committed result not published: %+v", s.Results())
	}
	storedTask, _ := s.Task(leased[0].ID)
	storedApproval, _ := s.Approval(approval.ID)
	storedBinding, _ := s.NodeGuardBinding("n1")
	if storedTask.Status != model.TaskFinished || storedApproval.Status != model.ApprovalApplied ||
		storedBinding.AppliedTableSHA != strings.Repeat("a", 64) {
		t.Fatalf("committed state not published: task=%+v approval=%+v binding=%+v", storedTask, storedApproval, storedBinding)
	}
	if !errors.Is(s.ReadyCheck(), errStoreDurabilityDegraded) {
		t.Fatalf("post-rename sync failure did not degrade readiness: %v", s.ReadyCheck())
	}
}
