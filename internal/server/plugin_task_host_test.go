package server

import (
	"context"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A plugin enqueues work only inside an operation the operator already
// approved, so the task it creates must be one an agent is handed. It used to
// be stored as "pending", a status the lease gate never delivers.
func TestPluginEnqueuedTaskIsDeliveredToItsNode(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	host := &pluginTaskHost{server: srv}
	taskID, err := host.Enqueue(context.Background(), plugin.HostTaskRequest{
		PluginID: "demo", ApprovalID: "ap-demo", NodeID: "node-a",
		Interpreter: "sh", Script: "echo applied", TimeoutSec: 30,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	task, ok := st.Task(taskID)
	if !ok {
		t.Fatalf("task %s was not stored", taskID)
	}
	if task.Status != model.TaskQueued || task.ApprovalID != "ap-demo" || task.ActorID != "plugin:demo" {
		t.Fatalf("stored task = status %q approval %q actor %q, want queued, ap-demo, plugin:demo", task.Status, task.ApprovalID, task.ActorID)
	}
	if view := srv.toTaskView(task); view.Status != model.TaskQueued || view.Origin != taskOriginApproval {
		t.Fatalf("view = status %q origin %q", view.Status, view.Origin)
	}

	leased, err := st.LeaseTasks("node-a", 10)
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(leased) != 1 || leased[0].ID != taskID {
		t.Fatalf("node-a leased %d tasks, want the plugin's task %s", len(leased), taskID)
	}
	if other, err := st.LeaseTasks("node-b", 10); err != nil || len(other) != 0 {
		t.Fatalf("node-b leased %d tasks (err %v), want none", len(other), err)
	}
}
