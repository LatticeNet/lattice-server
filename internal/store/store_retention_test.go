package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestAddTaskResultRetention verifies task results are bounded to maxTaskResults
// (oldest evicted) so on-disk state cannot grow without limit.
func TestAddTaskResultRetention(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// Seed state at exactly the cap (direct, to avoid maxTaskResults disk writes).
	s.state.Results = make([]model.TaskResult, 0, maxTaskResults)
	for i := 0; i < maxTaskResults; i++ {
		s.state.Results = append(s.state.Results, model.TaskResult{TaskID: fmt.Sprintf("old-%d", i)})
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "newest"}); err != nil {
		t.Fatalf("AddTaskResult: %v", err)
	}
	if got := len(s.state.Results); got != maxTaskResults {
		t.Fatalf("retained %d results, want cap %d", got, maxTaskResults)
	}
	last := s.state.Results[len(s.state.Results)-1]
	if last.TaskID != "newest" {
		t.Fatalf("newest result evicted; last TaskID = %q", last.TaskID)
	}
	if first := s.state.Results[0].TaskID; first == "old-0" {
		t.Fatalf("oldest result (old-0) should have been evicted, still at front")
	}
}

func TestTaskResultReceiptSurvivesDisplayHistoryPruning(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(statePath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTask(model.Task{
		ID: "task-replay", ApprovalID: "approval-replay", Targets: []string{"node-a"}, Status: model.TaskLeased,
		TargetLeases: map[string]model.TaskLease{"node-a": {LeaseID: "lease-a"}},
	}); err != nil {
		t.Fatal(err)
	}
	approval := model.Approval{
		ID: "approval-replay", NodeID: "node-a", Plugin: "nft", Action: "apply-ruleset:netguard-v1",
		Status: model.ApprovalApproved, Plan: "table inet lattice_guard {}",
	}
	if err := s.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	binding, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	result := model.TaskResult{
		TaskID: "task-replay", NodeID: "node-a", LeaseID: "lease-a", ExitCode: 0,
		Stdout: "applied", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
	}
	approval.Status = model.ApprovalApplied
	binding.AppliedTableSHA = strings.Repeat("a", 64)
	if committed, err := s.CompleteNetGuardTaskResult(result, approval, binding); !committed || err != nil {
		t.Fatalf("complete NetGuard result = committed %v, err %v", committed, err)
	}
	s.mu.Lock()
	s.state.Results = make([]model.TaskResult, maxTaskResults)
	for i := range s.state.Results {
		s.state.Results[i] = model.TaskResult{TaskID: fmt.Sprintf("later-%d", i), NodeID: "other"}
	}
	if _, err := s.persistState(s.jsonPersistState()); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	if _, ok := s.TaskResult(result.TaskID, result.NodeID); ok {
		t.Fatal("display result should have been pruned in the fixture")
	}
	if matches, found := s.TaskResultReceiptMatches(result); !found || !matches {
		t.Fatalf("receipt match = %v, found = %v", matches, found)
	}
	conflict := result
	conflict.Stdout = strings.ToUpper(conflict.Stdout)
	if matches, found := s.TaskResultReceiptMatches(conflict); !found || matches {
		t.Fatalf("conflicting receipt match = %v, found = %v", matches, found)
	}
	reopened, err := OpenWithCipher(statePath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if matches, found := reopened.TaskResultReceiptMatches(result); !found || !matches {
		t.Fatalf("reopened receipt match = %v, found = %v", matches, found)
	}
}
