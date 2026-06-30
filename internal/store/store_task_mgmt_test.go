package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

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
