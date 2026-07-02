package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newTaskExecutionDisabledTestServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:                 st,
		AdminPassword:         testAdminPass,
		TaskExecutionDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), st
}

func TestTaskExecutionKillSwitchBlocksQueueingAndLeasing(t *testing.T) {
	handler, st := newTaskExecutionDisabledTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	version := doJSON(t, handler, http.MethodGet, "/api/version", "", cookies, "")
	defer version.Body.Close()
	if version.StatusCode != http.StatusOK {
		t.Fatalf("version failed: %d", version.StatusCode)
	}
	var build BuildInfo
	if err := json.NewDecoder(version.Body).Decode(&build); err != nil {
		t.Fatal(err)
	}
	if !build.TaskExecutionDisabled {
		t.Fatalf("version should expose task execution kill switch: %+v", build)
	}

	create := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"echo hi"}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusConflict {
		t.Fatalf("task create status = %d, want 409", create.StatusCode)
	}
	if code := errorCodeFromHTTPResponse(t, create); code != apiErrorTaskExecutionDisabled {
		t.Fatalf("task create code = %q", code)
	}
	if tasks := st.Tasks(); len(tasks) != 0 {
		t.Fatalf("kill switch must not queue task, got %+v", tasks)
	}

	seed := model.Task{
		ID:          "task_seed",
		Targets:     []string{nodeID},
		Interpreter: "sh",
		Script:      "echo seed",
		TimeoutSec:  defaultTaskTimeoutSec,
		OutputLimit: defaultTaskOutputLimit,
		Status:      model.TaskQueued,
	}
	if err := st.CreateTask(seed); err != nil {
		t.Fatal(err)
	}

	leaseReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	leaseReq.Header.Set("Authorization", "Bearer "+nodeToken)
	lease := serveReq(handler, leaseReq)
	if lease.Code != http.StatusOK {
		t.Fatalf("agent lease status = %d", lease.Code)
	}
	if lease.Header().Get("X-Lattice-Task-Execution-Disabled") != "1" {
		t.Fatalf("lease response should expose disabled header, got %q", lease.Header().Get("X-Lattice-Task-Execution-Disabled"))
	}
	var leased []agentTaskView
	if err := json.NewDecoder(lease.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Fatalf("kill switch must return no leases, got %+v", leased)
	}
	if stored, ok := st.Task(seed.ID); !ok || stored.Status != model.TaskQueued {
		t.Fatalf("kill switch must leave queued task untouched: ok=%v task=%+v", ok, stored)
	}

	rerun := doJSON(t, handler, http.MethodPost, "/api/tasks/rerun",
		`{"id":"`+seed.ID+`"}`, cookies, csrf)
	defer rerun.Body.Close()
	if rerun.StatusCode != http.StatusConflict {
		t.Fatalf("rerun status = %d, want 409", rerun.StatusCode)
	}
	if code := errorCodeFromHTTPResponse(t, rerun); code != apiErrorTaskExecutionDisabled {
		t.Fatalf("rerun code = %q", code)
	}
	if tasks := st.Tasks(); len(tasks) != 1 {
		t.Fatalf("kill switch rerun should not create a child task, got %+v", tasks)
	}
}

func TestTaskExecutionKillSwitchBlocksApprovalApplyWithoutApproving(t *testing.T) {
	handler, st := newTaskExecutionDisabledTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, _ := enrollNode(t, handler, cookies, csrf)
	approval := model.Approval{
		ID:     "approval_kill_switch",
		NodeID: nodeID,
		Plugin: "manualtask",
		Action: "apply",
		Status: model.ApprovalPending,
	}
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}

	res := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+approval.ID+`","queue_apply":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("approval apply status = %d, want 409", res.StatusCode)
	}
	if code := errorCodeFromHTTPResponse(t, res); code != apiErrorTaskExecutionDisabled {
		t.Fatalf("approval apply code = %q", code)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalPending {
		t.Fatalf("kill switch must leave approval pending: ok=%v approval=%+v", ok, stored)
	}
	if tasks := st.Tasks(); len(tasks) != 0 {
		t.Fatalf("kill switch approval apply must not queue task, got %+v", tasks)
	}
}

func errorCodeFromHTTPResponse(t *testing.T, res *http.Response) string {
	t.Helper()
	var out model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode api error: %v", err)
	}
	return out.Error.Code
}
