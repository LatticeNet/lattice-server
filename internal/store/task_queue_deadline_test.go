package store

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func queuedTask(created time.Time) model.Task {
	return model.Task{
		ID: "task_x", Targets: []string{"node-a"}, Status: model.TaskQueued,
		Interpreter: "sh", Script: "true", CreatedAt: created,
	}
}

// The default has to be indefinite. Store-and-forward is the whole point of the
// queue: a node that is switched off overnight must still get its task.
func TestWithNoDeadlineATaskWaitsForeverAsItAlwaysHas(t *testing.T) {
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	task := queuedTask(created)
	now := created.Add(365 * 24 * time.Hour)
	if !taskTargetAwaitingResult(task, "node-a", nil, nil, nil, now, 0) {
		t.Error("a task with no deadline stopped being deliverable")
	}
	if TaskPastQueueDeadline(task, now, 0) {
		t.Error("a task with no deadline reported as past its deadline")
	}
}

// Past the deadline the task stops being offered. This is what makes "expired"
// honest: the console may only call a task terminal if the agent genuinely will
// not be handed it.
func TestPastTheDeadlineDeliveryIsWithdrawn(t *testing.T) {
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	task := queuedTask(created)
	deadline := 24 * time.Hour

	justInside := created.Add(deadline - time.Minute)
	if !taskTargetAwaitingResult(task, "node-a", nil, nil, nil, justInside, deadline) {
		t.Error("a task inside its deadline was withdrawn early")
	}
	if TaskPastQueueDeadline(task, justInside, deadline) {
		t.Error("a task inside its deadline reported as expired")
	}

	justOutside := created.Add(deadline + time.Minute)
	if taskTargetAwaitingResult(task, "node-a", nil, nil, nil, justOutside, deadline) {
		t.Error("an expired task is still being offered to its agent")
	}
	if !TaskPastQueueDeadline(task, justOutside, deadline) {
		t.Error("an expired task did not report as past its deadline")
	}
}

// Measured from creation, not from the last contact. A node that reconnects
// briefly every hour without ever running the task must not renew its own
// reprieve indefinitely.
func TestTheDeadlineIsMeasuredFromCreationNotFromContact(t *testing.T) {
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	task := queuedTask(created)
	task.TargetLeases = map[string]model.TaskLease{
		"node-a": {LeaseID: "lease_recent", StartedAt: created.Add(47 * time.Hour)},
	}
	task.Status = model.TaskLeased
	now := created.Add(48 * time.Hour)
	if !TaskPastQueueDeadline(task, now, 24*time.Hour) {
		t.Error("a recent lease renewed the deadline; it must run from CreatedAt")
	}
}

// A task with no CreatedAt (older rows, hand-built fixtures) must not be
// expired on the strength of a zero timestamp.
func TestATaskWithNoCreationTimeIsNeverExpired(t *testing.T) {
	task := queuedTask(time.Time{})
	if TaskPastQueueDeadline(task, time.Now(), time.Hour) {
		t.Error("a task with a zero CreatedAt was treated as expired")
	}
}

// The predicate tests above pass even when only one of the two delivery paths
// honours the deadline, which is exactly the bug this exists to catch: a fresh
// lease and a redelivery are gated by different functions, and the console had
// already started calling tasks expired while the agent was still being handed
// them. Drive the real lease API instead of the predicates.
func TestAnExpiredTaskIsNotHandedToTheAgentByEitherLeasePath(t *testing.T) {
	st, err := Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	old := time.Now().UTC().Add(-48 * time.Hour)
	mk := func(id string) {
		if err := st.CreateTask(model.Task{
			ID: id, Targets: []string{"node-a"}, Status: model.TaskQueued,
			Interpreter: "sh", Script: "true", TimeoutSec: 60, OutputLimit: 1024, CreatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("task_expired")

	// Deadline shorter than the task's age: neither the fresh-lease path nor a
	// redelivery may offer it. Asking twice covers both, because the first call
	// is what would issue the lease the second would redeliver.
	st.SetTaskQueueDeadline(24 * time.Hour)
	for _, attempt := range []string{"first", "second"} {
		got, err := st.LeaseTasks("node-a", 10)
		if err != nil {
			t.Fatalf("%s lease after expiry: %v", attempt, err)
		}
		if len(got) != 0 {
			t.Fatalf("%s lease handed out %d task(s) the console reports as expired", attempt, len(got))
		}
	}

	// Expiry is a policy, not a destructive edit: a second task of the same age
	// is deliverable the moment the operator clears the deadline. (The first
	// task is not reused here - nothing leased it, but keeping the two cases on
	// separate tasks means a live lease can never be mistaken for the deadline.)
	mk("task_still_wanted")
	st.SetTaskQueueDeadline(0)
	got, err := st.LeaseTasks("node-a", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("clearing the deadline should make both aged tasks deliverable, got %d", len(got))
	}
}
