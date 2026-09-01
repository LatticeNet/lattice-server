package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func seedTaskAndResults(t *testing.T, st interface {
	CreateTask(model.Task) error
	AddTaskResult(model.TaskResult) error
}) {
	t.Helper()
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	for i, tid := range []string{"task-a", "task-b"} {
		if err := st.CreateTask(model.Task{
			ID: tid, Targets: []string{"node-a", "node-b"}, Interpreter: "sh",
			Script: "echo hi", Status: "done", CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		for _, nid := range []string{"node-a", "node-b"} {
			if err := st.AddTaskResult(model.TaskResult{
				TaskID: tid, NodeID: nid, ExitCode: 0, Stdout: "out-" + tid + "-" + nid,
				FinishedAt: base.Add(time.Duration(i) * time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTaskViewReportsStalledLease(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)

	dead := time.Now().Add(-2 * time.Hour)
	if err := st.CreateTask(model.Task{
		ID: "task-stalled", Targets: []string{"node-a"}, Interpreter: "sh",
		Script: "echo hi", Status: model.TaskLeased, TimeoutSec: 60,
		TargetLeases: map[string]model.TaskLease{"node-a": {LeaseID: "l1", StartedAt: dead}},
		CreatedAt:    dead,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{
		ID: "task-running", Targets: []string{"node-a"}, Interpreter: "sh",
		Script: "echo hi", Status: model.TaskLeased, TimeoutSec: 3600,
		TargetLeases: map[string]model.TaskLease{"node-a": {LeaseID: "l2", StartedAt: time.Now()}},
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	res := doJSON(t, handler, http.MethodGet, "/api/tasks", "", cookies, "")
	defer res.Body.Close()
	var tasks []taskView
	if err := json.NewDecoder(res.Body).Decode(&tasks); err != nil {
		t.Fatalf("tasks list: %v", err)
	}
	byID := map[string]string{}
	for _, v := range tasks {
		byID[v.ID] = v.Status
	}
	if byID["task-stalled"] != "stalled" {
		t.Fatalf("dead-leased task status = %q want stalled", byID["task-stalled"])
	}
	if byID["task-running"] != "leased" {
		t.Fatalf("live-leased task status = %q want leased", byID["task-running"])
	}
}

func TestTaskResultsBareModeStaysArrayQueryModeEnvelopes(t *testing.T) {
	handler, st := newTestServer(t)
	seedTaskAndResults(t, st)
	cookies, _ := loginSession(t, handler)

	// Bare mode: unchanged array shape.
	bare := doJSON(t, handler, http.MethodGet, "/api/task-results", "", cookies, "")
	defer bare.Body.Close()
	var arr []taskResultView
	if err := json.NewDecoder(bare.Body).Decode(&arr); err != nil {
		t.Fatalf("bare task-results must stay an array: %v", err)
	}
	if len(arr) != 4 {
		t.Fatalf("bare task-results = %d, want 4", len(arr))
	}

	// Query mode: filter by task_id, enveloped.
	q := doJSON(t, handler, http.MethodGet, "/api/task-results?task_id=task-a", "", cookies, "")
	defer q.Body.Close()
	var env taskResultsQueryResponse
	if err := json.NewDecoder(q.Body).Decode(&env); err != nil {
		t.Fatalf("query task-results must be enveloped: %v", err)
	}
	if env.Total != 2 || len(env.Results) != 2 {
		t.Fatalf("task_id=task-a should match 2 results, got total=%d len=%d", env.Total, len(env.Results))
	}
	for _, r := range env.Results {
		if r.TaskID != "task-a" {
			t.Fatalf("filter leaked a foreign task: %+v", r)
		}
	}

	// node_id + limit/offset pagination.
	page := doJSON(t, handler, http.MethodGet, "/api/task-results?node_id=node-a&limit=1&offset=1", "", cookies, "")
	defer page.Body.Close()
	var penv taskResultsQueryResponse
	if err := json.NewDecoder(page.Body).Decode(&penv); err != nil {
		t.Fatal(err)
	}
	if penv.Total != 2 || len(penv.Results) != 1 || penv.Limit != 1 || penv.Offset != 1 {
		t.Fatalf("pagination envelope wrong: %+v", penv)
	}
	if penv.Results[0].NodeID != "node-a" {
		t.Fatalf("node_id filter leaked: %+v", penv.Results[0])
	}

	// Invalid pagination is rejected.
	bad := doJSON(t, handler, http.MethodGet, "/api/task-results?limit=999", "", cookies, "")
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("limit over max must 400, got %d", bad.StatusCode)
	}
}

func TestTaskResultsOmitOutputStripsBodiesAndReturnsAll(t *testing.T) {
	handler, st := newTestServer(t)
	seedTaskAndResults(t, st)
	cookies, _ := loginSession(t, handler)

	// omit_output alone: enveloped, every visible row, bodies stripped, sizes kept.
	res := doJSON(t, handler, http.MethodGet, "/api/task-results?omit_output=1", "", cookies, "")
	defer res.Body.Close()
	var env taskResultsQueryResponse
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		t.Fatalf("omit_output must be enveloped: %v", err)
	}
	if env.Total != 4 || len(env.Results) != 4 {
		t.Fatalf("omit_output without limit must return every row: total=%d len=%d", env.Total, len(env.Results))
	}
	for _, r := range env.Results {
		if r.Stdout != "" || r.Stderr != "" {
			t.Fatalf("omit_output leaked a body: %+v", r)
		}
		if r.StdoutBytes == 0 {
			t.Fatalf("omit_output must report the withheld size: %+v", r)
		}
	}

	// An explicit limit still paginates bodyless rows.
	page := doJSON(t, handler, http.MethodGet, "/api/task-results?omit_output=1&limit=1", "", cookies, "")
	defer page.Body.Close()
	var penv taskResultsQueryResponse
	if err := json.NewDecoder(page.Body).Decode(&penv); err != nil {
		t.Fatal(err)
	}
	if penv.Total != 4 || len(penv.Results) != 1 || penv.Limit != 1 {
		t.Fatalf("omit_output with limit wrong: %+v", penv)
	}

	// Plain query mode keeps its bodies: stripping is opt-in.
	full := doJSON(t, handler, http.MethodGet, "/api/task-results?task_id=task-a", "", cookies, "")
	defer full.Body.Close()
	var fenv taskResultsQueryResponse
	if err := json.NewDecoder(full.Body).Decode(&fenv); err != nil {
		t.Fatal(err)
	}
	for _, r := range fenv.Results {
		if r.Stdout == "" {
			t.Fatalf("plain query mode must keep bodies: %+v", r)
		}
		if r.StdoutBytes != 0 {
			t.Fatalf("byte counts belong to omit_output rows only: %+v", r)
		}
	}
}

func TestTasksQueryModeFiltersAndPaginates(t *testing.T) {
	handler, st := newTestServer(t)
	seedTaskAndResults(t, st)
	cookies, _ := loginSession(t, handler)

	bare := doJSON(t, handler, http.MethodGet, "/api/tasks", "", cookies, "")
	defer bare.Body.Close()
	var arr []taskView
	if err := json.NewDecoder(bare.Body).Decode(&arr); err != nil {
		t.Fatalf("bare tasks must stay an array: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("bare tasks = %d, want 2", len(arr))
	}

	q := doJSON(t, handler, http.MethodGet, "/api/tasks?node_id=node-a&limit=1", "", cookies, "")
	defer q.Body.Close()
	var env tasksQueryResponse
	if err := json.NewDecoder(q.Body).Decode(&env); err != nil {
		t.Fatalf("query tasks must be enveloped: %v", err)
	}
	if env.Total != 2 || len(env.Tasks) != 1 {
		t.Fatalf("node_id filter/limit wrong: total=%d len=%d", env.Total, len(env.Tasks))
	}
}

func TestApprovalsQueryModeFiltersByStatus(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	base := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	for i, spec := range []struct{ id, status string }{
		{"appr-1", "pending"},
		{"appr-2", "applied"},
		{"appr-3", "pending"},
	} {
		if err := st.UpsertApproval(model.Approval{
			ID: spec.id, NodeID: "node-a", Plugin: "nftpolicy", Action: "apply",
			Status: spec.status, CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	res := doJSON(t, handler, http.MethodGet, "/api/network/approvals?status=pending", "", cookies, "")
	defer res.Body.Close()
	var env approvalsQueryResponse
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		t.Fatalf("approvals query must be enveloped: %v", err)
	}
	if env.Total != 2 {
		t.Fatalf("status=pending should match 2, got %d", env.Total)
	}
	for _, a := range env.Approvals {
		if a.Status != "pending" {
			t.Fatalf("status filter leaked: %+v", a)
		}
	}
}
