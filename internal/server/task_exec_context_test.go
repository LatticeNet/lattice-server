package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The whole point of pinning: an agent restarted with different flags after a
// run must not change what that run's output means. Before this, the console
// read the live posture map, so re-reading last week's audit after an agent
// restart described a configuration the run never had.
func TestAResultKeepsThePostureItRanUnderWhenTheAgentIsReconfigured(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	result := model.TaskResult{
		TaskID: "task_a", NodeID: "node-a", ExitCode: 0, Stdout: "root=",
		FinishedAt: time.Now().UTC(),
	}
	ran := store.TaskExecContext{
		TaskID: "task_a", NodeID: "node-a", NonRoot: true,
		Sandbox: "linux-rlimit-process-group", ReportedAt: time.Now().UTC(), RecordedAt: time.Now().UTC(),
	}
	if err := st.AddTaskResultWithContext(result, &ran); err != nil {
		t.Fatal(err)
	}

	got, ok := st.TaskExecContext("task_a", "node-a")
	if !ok || !got.NonRoot {
		t.Fatalf("pinned context lost: ok=%v ctx=%+v", ok, got)
	}

	// The agent is now root-capable. The pinned context must not follow it.
	later := store.TaskExecContext{
		TaskID: "task_b", NodeID: "node-a", RootExec: true,
		ReportedAt: time.Now().UTC(), RecordedAt: time.Now().UTC(),
	}
	if err := st.AddTaskResultWithContext(
		model.TaskResult{TaskID: "task_b", NodeID: "node-a", FinishedAt: time.Now().UTC()}, &later); err != nil {
		t.Fatal(err)
	}
	got, _ = st.TaskExecContext("task_a", "node-a")
	if !got.NonRoot || got.RootExec {
		t.Errorf("the earlier run's posture followed the agent's reconfiguration: %+v", got)
	}
}

// A result recorded without a context (everything before this shipped, and any
// node that never reported a posture) must read as unknown, not as some default.
func TestAResultWithNoPinnedContextReportsUnknownRatherThanGuessing(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AddTaskResult(model.TaskResult{TaskID: "task_old", NodeID: "node-a", FinishedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.TaskExecContext("task_old", "node-a"); ok {
		t.Error("a result with no pinned context reported one")
	}
}
