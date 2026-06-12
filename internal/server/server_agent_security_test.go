package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func errorCodeFromRecorder(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out model.APIErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode api error: %v; body=%q", err, rec.Body.String())
	}
	return out.Error.Code
}

func TestAgentHelloRejectsInvalidNetworkMetadata(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	cases := []string{
		`{"node_id":"` + nodeID + `","public_ip":"127.0.0.1"}`,
		`{"node_id":"` + nodeID + `","public_ipv6":"::1"}`,
		`{"node_id":"` + nodeID + `","wireguard_ip":"10.66.0.1\nAddress = 0.0.0.0/0"}`,
		`{"node_id":"` + nodeID + `","wireguard_endpoint":"host.example.com:abc"}`,
		`{"node_id":"` + nodeID + `","wireguard_port":70000}`,
	}
	for _, body := range cases {
		rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", body, nodeToken)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid network metadata should be rejected, got %d for %s", rec.Code, body)
		}
	}
}

func TestAgentPostEndpointsAcceptBearerToken(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	cases := []struct {
		name string
		path string
		body string
	}{
		{name: "hello", path: "/api/agent/hello", body: `{"node_id":"` + nodeID + `","version":"test"}`},
		{name: "metrics", path: "/api/agent/metrics", body: `{"node_id":"` + nodeID + `","version":"test","metrics":{}}`},
		{name: "monitor result", path: "/api/agent/monitor-result", body: `{"node_id":"` + nodeID + `","result":{"monitor_id":"mon-a","success":true}}`},
		{name: "event", path: "/api/agent/event", body: `{"node_id":"` + nodeID + `","kind":"agent.test","message":"ok"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+nodeToken)
			rec := serveReq(handler, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected bearer auth to work for %s, got %d (%s)", tc.path, rec.Code, rec.Body.String())
			}
		})
	}

	create := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"echo ok"}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("task create failed: %d", create.StatusCode)
	}
	tasksReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	tasksReq.Header.Set("Authorization", "Bearer "+nodeToken)
	tasksRec := serveReq(handler, tasksReq)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d", tasksRec.Code)
	}
	var leased []map[string]any
	if err := json.NewDecoder(tasksRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	taskID, _ := leased[0]["id"].(string)
	leaseID, _ := leased[0]["lease_id"].(string)
	result := `{"node_id":"` + nodeID + `","result":{"task_id":"` + taskID + `","lease_id":"` + leaseID + `","exit_code":0}}`
	req := httptest.NewRequest(http.MethodPost, "/api/agent/task-result", strings.NewReader(result))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+nodeToken)
	rec := serveReq(handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected bearer auth to work for task result, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAgentPostEndpointsRejectBodyTokenWithoutBearer(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	cases := []struct {
		name string
		path string
		body string
	}{
		{name: "hello", path: "/api/agent/hello", body: `{"node_id":"` + nodeID + `","token":"` + nodeToken + `","version":"test"}`},
		{name: "metrics", path: "/api/agent/metrics", body: `{"node_id":"` + nodeID + `","token":"` + nodeToken + `","metrics":{}}`},
		{name: "monitor result", path: "/api/agent/monitor-result", body: `{"node_id":"` + nodeID + `","token":"` + nodeToken + `","result":{"monitor_id":"mon-a","success":true}}`},
		{name: "event", path: "/api/agent/event", body: `{"node_id":"` + nodeID + `","token":"` + nodeToken + `","kind":"agent.test","message":"ok"}`},
		{name: "task result", path: "/api/agent/task-result", body: `{"node_id":"` + nodeID + `","token":"` + nodeToken + `","result":{"task_id":"task-a","lease_id":"lease-a","exit_code":0}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRaw(t, handler, http.MethodPost, tc.path, tc.body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("body token must be rejected for %s, got %d (%s)", tc.path, rec.Code, rec.Body.String())
			}
			if code := errorCodeFromRecorder(t, rec); code != "invalid_node_token" {
				t.Fatalf("expected invalid_node_token, got %q", code)
			}
		})
	}
}

func TestAgentGenericEventAuditUsesRequestID(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/event",
		`{"node_id":"`+nodeID+`","kind":"agent.test","message":"ok"}`, nodeToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent event failed: %d (%s)", rec.Code, rec.Body.String())
	}
	assertRecorderAuditCorrelation(t, st, rec, "agent.event", "")
}

func TestAgentSecurityFailuresUseStableErrorCodes(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	invalidToken := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics",
		`{"node_id":"`+nodeID+`","metrics":{}}`, "wrong-token")
	if invalidToken.Code != http.StatusUnauthorized {
		t.Fatalf("invalid node token status = %d", invalidToken.Code)
	}
	if code := errorCodeFromRecorder(t, invalidToken); code != "invalid_node_token" {
		t.Fatalf("invalid node token code = %q", code)
	}

	create := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"printf 12345678","output_limit":8}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("task create failed: %d", create.StatusCode)
	}

	tasksReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	tasksReq.Header.Set("Authorization", "Bearer "+nodeToken)
	tasksRec := serveReq(handler, tasksReq)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d", tasksRec.Code)
	}
	var leased []map[string]any
	if err := json.NewDecoder(tasksRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	taskID, _ := leased[0]["id"].(string)
	leaseID, _ := leased[0]["lease_id"].(string)

	wrongLease := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result",
		`{"node_id":"`+nodeID+`","result":{"task_id":"`+taskID+`","lease_id":"lease_wrong","exit_code":0}}`, nodeToken)
	if wrongLease.Code != http.StatusForbidden {
		t.Fatalf("wrong lease status = %d", wrongLease.Code)
	}
	if code := errorCodeFromRecorder(t, wrongLease); code != "invalid_task_lease" {
		t.Fatalf("wrong lease code = %q", code)
	}

	tooLarge := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result",
		`{"node_id":"`+nodeID+`","result":{"task_id":"`+taskID+`","lease_id":"`+leaseID+`","exit_code":1,"stdout":"123456789"}}`, nodeToken)
	if tooLarge.Code != http.StatusBadRequest {
		t.Fatalf("oversize output status = %d", tooLarge.Code)
	}
	if code := errorCodeFromRecorder(t, tooLarge); code != "task_output_limit_exceeded" {
		t.Fatalf("oversize output code = %q", code)
	}
}

func TestApproveIsIdempotentWhenQueueingApply(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a","public_tcp":[443]}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", plan.StatusCode)
	}
	var approval struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	body := `{"approval_id":"` + approval.ID + `","queue_apply":true}`
	for i := 0; i < 2; i++ {
		res := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve", body, cookies, csrf)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("approve %d failed: %d", i+1, res.StatusCode)
		}
	}
	tasks := doJSON(t, handler, http.MethodGet, "/api/tasks", "", cookies, "")
	defer tasks.Body.Close()
	var queued []map[string]any
	if err := json.NewDecoder(tasks.Body).Decode(&queued); err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 {
		t.Fatalf("approval should queue exactly one apply task: %+v", queued)
	}
}

func TestApplyScriptForUsesPlanSafeHeredocDelimiters(t *testing.T) {
	cases := []struct {
		plugin    string
		plan      string
		forbidden string
	}{
		{plugin: "nft", plan: "table inet x {\n}\nEOF\npayload", forbidden: "EOF"},
		{plugin: "cftunnel", plan: "ingress:\nLATTICE_CF_EOF\npayload", forbidden: "LATTICE_CF_EOF"},
		{plugin: "wireguard", plan: "[Interface]\nLATTICE_WG_EOF\npayload", forbidden: "LATTICE_WG_EOF"},
	}
	for _, tc := range cases {
		t.Run(tc.plugin, func(t *testing.T) {
			script := applyScriptFor(model.Approval{Plugin: tc.plugin, Plan: tc.plan})
			if strings.Contains(script, "<<'"+tc.forbidden+"'") {
				t.Fatalf("apply script used a delimiter controlled by plan content:\n%s", script)
			}
			if strings.Contains(script, "payload"+tc.forbidden) {
				t.Fatalf("apply script appended delimiter to final plan line:\n%s", script)
			}
		})
	}
}

func TestAgentTaskResultRequiresMatchingLease(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	create := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"echo ok"}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("task create failed: %d", create.StatusCode)
	}

	tasksReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	tasksReq.Header.Set("Authorization", "Bearer "+nodeToken)
	tasksRec := serveReq(handler, tasksReq)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d", tasksRec.Code)
	}
	var leased []map[string]any
	if err := json.NewDecoder(tasksRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected one leased task, got %+v", leased)
	}
	taskID, _ := leased[0]["id"].(string)
	leaseID, _ := leased[0]["lease_id"].(string)
	if taskID == "" || leaseID == "" {
		t.Fatalf("leased task must include id and lease_id: %+v", leased[0])
	}

	missingLease := `{"node_id":"` + nodeID + `","result":{"task_id":"` + taskID + `","exit_code":0}}`
	missingLeaseRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", missingLease, nodeToken)
	if missingLeaseRec.Code != http.StatusForbidden {
		t.Fatalf("missing lease_id must be forbidden, got %d", missingLeaseRec.Code)
	}
	assertRecorderAuditCorrelation(t, st, missingLeaseRec, "task.result", "")
	wrongLease := `{"node_id":"` + nodeID + `","result":{"task_id":"` + taskID + `","lease_id":"lease_wrong","exit_code":0}}`
	wrongLeaseRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", wrongLease, nodeToken)
	if wrongLeaseRec.Code != http.StatusForbidden {
		t.Fatalf("wrong lease_id must be forbidden, got %d", wrongLeaseRec.Code)
	}
	assertRecorderAuditCorrelation(t, st, wrongLeaseRec, "task.result", "")
	correctLease := `{"node_id":"` + nodeID + `","result":{"task_id":"` + taskID + `","lease_id":"` + leaseID + `","exit_code":0}}`
	correctLeaseRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", correctLease, nodeToken)
	if correctLeaseRec.Code != http.StatusOK {
		t.Fatalf("matching lease_id should be accepted, got %d (%s)", correctLeaseRec.Code, correctLeaseRec.Body.String())
	}
	assertRecorderAuditCorrelation(t, st, correctLeaseRec, "task.result", "")

	stored := st.Results()
	if len(stored) != 1 {
		t.Fatalf("expected one stored result, got %+v", stored)
	}
	if stored[0].LeaseID != "" {
		t.Fatalf("stored task result must not retain lease_id: %+v", stored[0])
	}

	results := doJSON(t, handler, http.MethodGet, "/api/task-results", "", cookies, "")
	defer results.Body.Close()
	if results.StatusCode != http.StatusOK {
		t.Fatalf("task results failed: %d", results.StatusCode)
	}
	var visible []map[string]any
	if err := json.NewDecoder(results.Body).Decode(&visible); err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 {
		t.Fatalf("expected one visible result, got %+v", visible)
	}
	if _, ok := visible[0]["lease_id"]; ok {
		t.Fatalf("control plane task result leaked lease_id: %+v", visible[0])
	}
}

func TestAgentTaskLeaseResponseIsMinimized(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	create := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"echo ok"}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("task create failed: %d", create.StatusCode)
	}

	tasksReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	tasksReq.Header.Set("Authorization", "Bearer "+nodeToken)
	tasksRec := serveReq(handler, tasksReq)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d", tasksRec.Code)
	}
	var leased []map[string]any
	if err := json.NewDecoder(tasksRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected one leased task, got %+v", leased)
	}
	for _, field := range []string{"id", "lease_id", "interpreter", "script", "timeout_sec", "output_limit"} {
		if _, ok := leased[0][field]; !ok {
			t.Fatalf("leased task missing required field %q: %+v", field, leased[0])
		}
	}
	for _, field := range []string{"actor_id", "token_id", "targets", "leased_by", "created_at", "started_at", "finished_at"} {
		if _, ok := leased[0][field]; ok {
			t.Fatalf("leased task exposed control-plane field %q: %+v", field, leased[0])
		}
	}
}

func TestAgentTaskResultRejectsOutputOverTaskLimit(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	create := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"printf 12345678","output_limit":8}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("task create failed: %d", create.StatusCode)
	}

	tasksReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	tasksReq.Header.Set("Authorization", "Bearer "+nodeToken)
	tasksRec := serveReq(handler, tasksReq)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d", tasksRec.Code)
	}
	var leased []map[string]any
	if err := json.NewDecoder(tasksRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	taskID, _ := leased[0]["id"].(string)
	leaseID, _ := leased[0]["lease_id"].(string)

	for _, field := range []string{"stdout", "stderr", "error"} {
		tooLarge := `{"node_id":"` + nodeID + `","result":{"task_id":"` + taskID + `","lease_id":"` + leaseID + `","exit_code":1,"` + field + `":"123456789"}}`
		rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", tooLarge, nodeToken)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("oversize %s must be rejected, got %d", field, rec.Code)
		}
		assertRecorderAuditCorrelation(t, st, rec, "task.result", "")
	}
	allowed := `{"node_id":"` + nodeID + `","result":{"task_id":"` + taskID + `","lease_id":"` + leaseID + `","exit_code":0,"stdout":"12345678"}}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", allowed, nodeToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("stdout at limit should be accepted, got %d (%s)", rec.Code, rec.Body.String())
	}
	assertRecorderAuditCorrelation(t, st, rec, "task.result", "")
}

func TestControlPlaneTaskListDoesNotExposeTaskSecrets(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	create := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"echo private-token"}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("task create failed: %d", create.StatusCode)
	}

	tasksReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	tasksReq.Header.Set("Authorization", "Bearer "+nodeToken)
	tasksRec := serveReq(handler, tasksReq)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d", tasksRec.Code)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/tasks", "", cookies, "")
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("task list failed: %d", list.StatusCode)
	}
	var visible []map[string]any
	if err := json.NewDecoder(list.Body).Decode(&visible); err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 {
		t.Fatalf("expected one visible task, got %+v", visible)
	}
	if _, ok := visible[0]["lease_id"]; ok {
		t.Fatalf("control plane task view leaked lease_id: %+v", visible[0])
	}
	if _, ok := visible[0]["script"]; ok {
		t.Fatalf("control plane task view leaked script: %+v", visible[0])
	}
	if visible[0]["script_sha256"] == "" {
		t.Fatalf("control plane task view must include script hash: %+v", visible[0])
	}
	if visible[0]["script_size_bytes"] != float64(len("echo private-token")) {
		t.Fatalf("control plane task view has wrong script size: %+v", visible[0])
	}
}
