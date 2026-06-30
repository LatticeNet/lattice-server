package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestTaskCancelDeleteRerunHTTP exercises the task management endpoints end to
// end: rerun re-creates from the stored script (whose body never leaves the
// server), cancel only succeeds on queued tasks, and delete removes a task.
func TestTaskCancelDeleteRerunHTTP(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	createRes := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["node-a"],"interpreter":"sh","script":"echo hi"}`, cookies, csrf)
	defer createRes.Body.Close()
	if createRes.StatusCode != http.StatusOK {
		t.Fatalf("create task failed: %d", createRes.StatusCode)
	}
	var created struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		ScriptSHA256 string `json:"script_sha256"`
		Script       string `json:"script"` // must remain absent from the view
	}
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Status != model.TaskQueued {
		t.Fatalf("new task status = %q want queued", created.Status)
	}
	if created.Script != "" {
		t.Fatalf("task view leaked script body: %q", created.Script)
	}

	// Rerun mints a new queued task with the same script (matched by SHA).
	rerunRes := doJSON(t, handler, http.MethodPost, "/api/tasks/rerun",
		`{"id":"`+created.ID+`"}`, cookies, csrf)
	defer rerunRes.Body.Close()
	if rerunRes.StatusCode != http.StatusOK {
		t.Fatalf("rerun failed: %d", rerunRes.StatusCode)
	}
	var rerun struct {
		ID            string   `json:"id"`
		Status        string   `json:"status"`
		ScriptSHA256  string   `json:"script_sha256"`
		RerunOfTaskID string   `json:"rerun_of_task_id"`
		RerunOfNodeID string   `json:"rerun_of_node_id"`
		Targets       []string `json:"targets"`
	}
	if err := json.NewDecoder(rerunRes.Body).Decode(&rerun); err != nil {
		t.Fatal(err)
	}
	if rerun.ID == created.ID {
		t.Fatal("rerun should mint a new task id")
	}
	if rerun.Status != model.TaskQueued {
		t.Fatalf("rerun status = %q want queued", rerun.Status)
	}
	if rerun.ScriptSHA256 != created.ScriptSHA256 {
		t.Fatalf("rerun script sha %q != original %q", rerun.ScriptSHA256, created.ScriptSHA256)
	}
	if rerun.RerunOfTaskID != created.ID || rerun.RerunOfNodeID != "" {
		t.Fatalf("rerun ancestry = task:%q node:%q want task:%q node empty", rerun.RerunOfTaskID, rerun.RerunOfNodeID, created.ID)
	}

	// Rerun-node mints a child task for exactly one target while preserving
	// ancestry under the original task.
	rerunNodeRes := doJSON(t, handler, http.MethodPost, "/api/tasks/rerun-node",
		`{"id":"`+created.ID+`","node_id":"node-a"}`, cookies, csrf)
	defer rerunNodeRes.Body.Close()
	if rerunNodeRes.StatusCode != http.StatusOK {
		t.Fatalf("rerun-node failed: %d", rerunNodeRes.StatusCode)
	}
	var rerunNode struct {
		ID            string   `json:"id"`
		RerunOfTaskID string   `json:"rerun_of_task_id"`
		RerunOfNodeID string   `json:"rerun_of_node_id"`
		Targets       []string `json:"targets"`
	}
	if err := json.NewDecoder(rerunNodeRes.Body).Decode(&rerunNode); err != nil {
		t.Fatal(err)
	}
	if rerunNode.RerunOfTaskID != created.ID || rerunNode.RerunOfNodeID != "node-a" ||
		len(rerunNode.Targets) != 1 || rerunNode.Targets[0] != "node-a" {
		t.Fatalf("bad rerun-node view: %+v", rerunNode)
	}

	// Cancel the original (queued) task.
	cancelRes := doJSON(t, handler, http.MethodPost, "/api/tasks/cancel",
		`{"id":"`+created.ID+`"}`, cookies, csrf)
	cancelRes.Body.Close()
	if cancelRes.StatusCode != http.StatusOK {
		t.Fatalf("cancel failed: %d", cancelRes.StatusCode)
	}
	if tk, ok := st.Task(created.ID); !ok || tk.Status != model.TaskCancelled {
		t.Fatalf("task not cancelled: ok=%v status=%q", ok, tk.Status)
	}

	// Cancelling an already-cancelled (non-queued) task is a conflict.
	reCancel := doJSON(t, handler, http.MethodPost, "/api/tasks/cancel",
		`{"id":"`+created.ID+`"}`, cookies, csrf)
	reCancel.Body.Close()
	if reCancel.StatusCode != http.StatusConflict {
		t.Fatalf("re-cancel status = %d want 409", reCancel.StatusCode)
	}

	// Delete the rerun task.
	delRes := doJSON(t, handler, http.MethodPost, "/api/tasks/delete",
		`{"id":"`+rerun.ID+`"}`, cookies, csrf)
	delRes.Body.Close()
	if delRes.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", delRes.StatusCode)
	}
	if _, ok := st.Task(rerun.ID); ok {
		t.Fatal("rerun task still present after delete")
	}

	// Deleting a missing task is a 404.
	del404 := doJSON(t, handler, http.MethodPost, "/api/tasks/delete",
		`{"id":"task_missing"}`, cookies, csrf)
	del404.Body.Close()
	if del404.StatusCode != http.StatusNotFound {
		t.Fatalf("delete missing status = %d want 404", del404.StatusCode)
	}
}
