package store

import (
	"errors"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A row the plugin task host stored as "pending" was never delivered. It is
// not migrated or delivered late; it can be cancelled like a queued task.
func TestCancelTaskClosesAPendingRow(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "t-pending", Targets: []string{"node-a"}, Interpreter: "sh", Script: "echo", Status: TaskPending}); err != nil {
		t.Fatal(err)
	}
	if leased, err := st.LeaseTasks("node-a", 10); err != nil || len(leased) != 0 {
		t.Fatalf("a pending row was leased: %d tasks, err %v", len(leased), err)
	}
	cancelled, err := st.CancelTask("t-pending")
	if err != nil {
		t.Fatalf("cancel pending: %v", err)
	}
	if cancelled.Status != model.TaskCancelled || cancelled.FinishedAt.IsZero() {
		t.Fatalf("cancelled row = status %q finished_at %v", cancelled.Status, cancelled.FinishedAt)
	}
	if _, err := st.CancelTask("t-pending"); !errors.Is(err, ErrTaskNotCancelable) {
		t.Fatalf("cancelling it again = %v, want ErrTaskNotCancelable", err)
	}
}
