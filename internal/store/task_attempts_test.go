package store

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// backdateLease moves a node's lease on a task into the past so the next poll
// sees it as certainly dead, the way TestTaskLeaseExpiryReleasesDeadLease does.
func backdateLease(t *testing.T, s *Store, taskID, nodeID string, age time.Duration) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	task, ok := s.state.Tasks[taskID]
	if !ok {
		t.Fatalf("backdate: task %s missing", taskID)
	}
	lease := task.TargetLeases[nodeID]
	lease.StartedAt = time.Now().UTC().Add(-age)
	task.TargetLeases[nodeID] = lease
	task.StartedAt = lease.StartedAt
	s.state.Tasks[taskID] = task
}

func TestTaskReleaseCountsAttemptsAndStallsAtCap(t *testing.T) {
	cases := []struct {
		name string
		// recorded attempts before the dead lease is re-leased; zero means no
		// record, which is what a task leased before the counter existed has
		recorded     int
		wantLeased   bool
		wantAttempts int
		wantReason   string
	}{
		{name: "first re-lease counts the original lease as attempt one", recorded: 0, wantLeased: true, wantAttempts: 2},
		{name: "second re-lease is attempt three", recorded: 2, wantLeased: true, wantAttempts: 3},
		{name: "a third dead lease stalls the target instead of re-leasing", recorded: 3, wantLeased: false, wantAttempts: 3, wantReason: TaskStalledAgentLostReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			if err := s.CreateTask(model.Task{ID: "task-loop", Targets: []string{"n1"}, TimeoutSec: 60, Status: model.TaskQueued}); err != nil {
				t.Fatalf("create: %v", err)
			}
			if first, err := s.LeaseTasks("n1", 3); err != nil || len(first) != 1 {
				t.Fatalf("first lease: len=%d err=%v", len(first), err)
			}
			backdateLease(t, s, "task-loop", "n1", 20*time.Minute)
			key := taskResultReceiptKey("task-loop", "n1")
			s.mu.Lock()
			if tc.recorded == 0 {
				delete(s.state.TaskTargetStates, key)
			} else {
				s.state.TaskTargetStates[key] = TaskTargetState{TaskID: "task-loop", NodeID: "n1", Attempts: tc.recorded}
			}
			s.mu.Unlock()

			again, err := s.LeaseTasks("n1", 3)
			if err != nil {
				t.Fatalf("re-lease: %v", err)
			}
			if got := len(again) == 1; got != tc.wantLeased {
				t.Fatalf("re-leased = %v want %v", got, tc.wantLeased)
			}
			progress, ok := s.TaskProgress("task-loop", time.Now().UTC())
			if !ok {
				t.Fatalf("no progress for a leased task")
			}
			target := progress.Targets["n1"]
			if target.Attempts != tc.wantAttempts || target.StalledReason != tc.wantReason {
				t.Fatalf("target = %+v want attempts %d reason %q", target, tc.wantAttempts, tc.wantReason)
			}
			if tc.wantLeased {
				return
			}
			// Stalled is final: a later poll with an even older lease still
			// gets nothing, and the task reads as stalled for the reason given.
			backdateLease(t, s, "task-loop", "n1", time.Hour)
			if later, err := s.LeaseTasks("n1", 3); err != nil || len(later) != 0 {
				t.Fatalf("stalled target re-leased: len=%d err=%v", len(later), err)
			}
			if !s.TaskProgressStalled("task-loop", time.Now().UTC()) {
				t.Fatalf("stalled target should read as stalled")
			}
			if target.Status != TaskStalled {
				t.Fatalf("target status = %q want %q", target.Status, TaskStalled)
			}
		})
	}
}

func agentUpdateAction(t *testing.T, targetVersion string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"node_id": "n1", "target_version": targetVersion})
	if err != nil {
		t.Fatal(err)
	}
	return AgentUpdateActionPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func TestAgentUpdateReleaseStallsWhenSuperseded(t *testing.T) {
	cases := []struct {
		name        string
		target      string
		nodeVersion string
		lastApplied string
		wantLeased  bool
		wantReason  string
	}{
		{name: "node already reports a newer agent", target: "v0.3.9-alpha.4", nodeVersion: "v0.3.9-alpha.5", wantReason: "superseded by v0.3.9-alpha.5"},
		{name: "a later policy applied a newer agent the node has not reported", target: "v0.3.9-alpha.4", nodeVersion: "v0.3.9-alpha.3", lastApplied: "v0.3.9-alpha.6", wantReason: "superseded by v0.3.9-alpha.6"},
		{name: "the newest of the two sources is the one named", target: "v0.3.9-alpha.4", nodeVersion: "v0.3.10", lastApplied: "v0.3.9-alpha.6", wantReason: "superseded by v0.3.10"},
		{name: "same version is not a downgrade", target: "v0.3.9-alpha.5", nodeVersion: "v0.3.9-alpha.5", wantLeased: true},
		{name: "node still older re-leases", target: "v0.3.9-alpha.5", nodeVersion: "v0.3.9-alpha.4", wantLeased: true},
		{name: "a build tag that cannot be ordered re-leases", target: "v0.3.9-alpha.4", nodeVersion: "custom-2026", wantLeased: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			if err := s.UpsertNode(model.Node{ID: "n1", AgentVersion: tc.nodeVersion}); err != nil {
				t.Fatalf("node: %v", err)
			}
			if err := s.UpsertApproval(model.Approval{ID: "ap-update", NodeID: "n1", Plugin: AgentUpdatePlugin, Action: agentUpdateAction(t, tc.target), Status: model.ApprovalApproved}); err != nil {
				t.Fatalf("approval: %v", err)
			}
			if tc.lastApplied != "" {
				if err := s.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{NodeID: "n1", TargetVersion: tc.lastApplied, LastAppliedVersion: tc.lastApplied}); err != nil {
					t.Fatalf("policy: %v", err)
				}
			}
			if err := s.CreateTask(model.Task{ID: "task-update", ApprovalID: "ap-update", Targets: []string{"n1"}, TimeoutSec: 600, Status: model.TaskQueued}); err != nil {
				t.Fatalf("create: %v", err)
			}
			// The first lease is never judged here: plan time already refused
			// a downgrade, and a forced one is the operator's decision.
			if first, err := s.LeaseTasks("n1", 3); err != nil || len(first) != 1 {
				t.Fatalf("first lease: len=%d err=%v", len(first), err)
			}
			backdateLease(t, s, "task-update", "n1", 20*time.Minute)

			again, err := s.LeaseTasks("n1", 3)
			if err != nil {
				t.Fatalf("re-lease: %v", err)
			}
			if got := len(again) == 1; got != tc.wantLeased {
				t.Fatalf("re-leased = %v want %v", got, tc.wantLeased)
			}
			progress, ok := s.TaskProgress("task-update", time.Now().UTC())
			if !ok {
				t.Fatalf("no progress for a leased task")
			}
			if got := progress.Targets["n1"].StalledReason; got != tc.wantReason {
				t.Fatalf("stalled reason = %q want %q", got, tc.wantReason)
			}
		})
	}
}

func TestTaskProgressReportsAttemptsLeaseAgeAndStall(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	now := time.Now().UTC()
	live := now.Add(-41 * time.Minute)
	dead := now.Add(-2 * time.Hour)
	if err := s.CreateTask(model.Task{ID: "fanout", Targets: []string{"live", "dead", "gone", "waiting", "done"}, Status: model.TaskLeased, TimeoutSec: 3600,
		TargetLeases: map[string]model.TaskLease{
			"live": {LeaseID: "l1", StartedAt: live},
			"dead": {LeaseID: "l2", StartedAt: dead},
			"gone": {LeaseID: "l3", StartedAt: dead},
			"done": {LeaseID: "l4", StartedAt: live},
		}}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.AddTaskResult(model.TaskResult{TaskID: "fanout", NodeID: "done", ExitCode: 2, FinishedAt: now}); err != nil {
		t.Fatalf("result: %v", err)
	}
	s.mu.Lock()
	s.state.TaskTargetStates[taskResultReceiptKey("fanout", "live")] = TaskTargetState{TaskID: "fanout", NodeID: "live", Attempts: 2}
	s.state.TaskTargetStates[taskResultReceiptKey("fanout", "gone")] = TaskTargetState{TaskID: "fanout", NodeID: "gone", Attempts: 3, StalledReason: TaskStalledAgentLostReason, StalledAt: now}
	s.mu.Unlock()

	progress, ok := s.TaskProgress("fanout", now)
	if !ok {
		t.Fatalf("no progress for a leased task")
	}
	if progress.Stalled {
		t.Fatalf("a live lease on one target means the task is still running")
	}
	cases := map[string]TaskTargetProgress{
		"live":    {Status: model.TaskLeased, Attempts: 2, LeaseAge: 41 * time.Minute, LeaseLive: true},
		"dead":    {Status: TaskStalled, Attempts: 1, LeaseAge: 2 * time.Hour}, // no record: the lease itself is attempt one
		"gone":    {Status: TaskStalled, Attempts: 3, LeaseAge: 2 * time.Hour, StalledReason: TaskStalledAgentLostReason},
		"waiting": {Status: model.TaskQueued},
		"done":    {Status: model.TaskFailed, Attempts: 1, LeaseAge: 41 * time.Minute, LeaseLive: true, Answered: true, AnsweredFailure: true},
	}
	for target, want := range cases {
		got := progress.Targets[target]
		// Lease age is measured against the clock passed in, so it is exact.
		if got != want {
			t.Fatalf("target %s = %+v want %+v", target, got, want)
		}
	}
	if _, ok := s.TaskProgress("missing", now); ok {
		t.Fatalf("progress reported for a missing task")
	}
}

func TestTaskTargetStatesPersistAndPruneWithTheTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.CreateTask(model.Task{ID: "task-keep", Targets: []string{"n1"}, TimeoutSec: 60, Status: model.TaskQueued}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if first, err := s.LeaseTasks("n1", 3); err != nil || len(first) != 1 {
		t.Fatalf("first lease: len=%d err=%v", len(first), err)
	}
	backdateLease(t, s, "task-keep", "n1", 20*time.Minute)
	if again, err := s.LeaseTasks("n1", 3); err != nil || len(again) != 1 {
		t.Fatalf("re-lease: len=%d err=%v", len(again), err)
	}

	reopened, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	progress, ok := reopened.TaskProgress("task-keep", time.Now().UTC())
	if !ok || progress.Targets["n1"].Attempts != 2 {
		t.Fatalf("attempts after reopen = %+v ok=%v want 2", progress.Targets["n1"], ok)
	}
	if err := reopened.DeleteTask("task-keep"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	reopened.mu.Lock()
	remaining := len(reopened.state.TaskTargetStates)
	reopened.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("target states not pruned with the task: %d left", remaining)
	}
}
