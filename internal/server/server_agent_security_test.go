package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
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

func TestAgentBearerAuthTouchesNodeTokenLastUsedAt(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	invalid := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello",
		`{"node_id":"`+nodeID+`","version":"test"}`, nodeToken+"-wrong")
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status = %d", invalid.Code)
	}
	n, ok := st.Node(nodeID)
	if !ok {
		t.Fatal("node missing")
	}
	if !n.TokenLastUsedAt.IsZero() {
		t.Fatalf("failed auth must not touch token last-used timestamp: %s", n.TokenLastUsedAt)
	}

	valid := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello",
		`{"node_id":"`+nodeID+`","version":"test"}`, nodeToken)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid token status = %d (%s)", valid.Code, valid.Body.String())
	}
	n, ok = st.Node(nodeID)
	if !ok || n.TokenLastUsedAt.IsZero() {
		t.Fatalf("successful auth did not touch token last-used timestamp: ok=%v node=%+v", ok, n)
	}

	nodes := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, csrf)
	defer nodes.Body.Close()
	if nodes.StatusCode != http.StatusOK {
		t.Fatalf("node list status = %d", nodes.StatusCode)
	}
	var views []struct {
		ID              string    `json:"id"`
		TokenLastUsedAt time.Time `json:"token_last_used_at"`
	}
	if err := json.NewDecoder(nodes.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		if view.ID == nodeID {
			if view.TokenLastUsedAt.IsZero() {
				t.Fatalf("node view omitted token_last_used_at: %+v", view)
			}
			return
		}
	}
	t.Fatalf("node %q missing from node views: %+v", nodeID, views)
}

func TestAgentSourceAllowlistRestrictsBearerAuth(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	update := doJSON(t, handler, http.MethodPost, "/api/nodes/update", `{
		"node_id":"`+nodeID+`",
		"name":"Node A",
		"agent_source_allowlist":["198.51.100.10/32"]
	}`, cookies, csrf)
	update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("set allowlist status = %d", update.StatusCode)
	}

	spoofed := httptest.NewRequest(http.MethodPost, "/api/agent/hello",
		strings.NewReader(`{"node_id":"`+nodeID+`","version":"test"}`))
	spoofed.RemoteAddr = "203.0.113.20:1234"
	spoofed.Header.Set("Content-Type", "application/json")
	spoofed.Header.Set("Authorization", "Bearer "+nodeToken)
	spoofed.Header.Set("X-Forwarded-For", "198.51.100.10")
	denied := serveReq(handler, spoofed)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed source must be rejected when TrustProxy=false, got %d (%s)", denied.Code, denied.Body.String())
	}
	n, ok := st.Node(nodeID)
	if !ok || !n.TokenLastUsedAt.IsZero() {
		t.Fatalf("source-denied auth must not touch token timestamp: ok=%v node=%+v", ok, n)
	}

	allowed := httptest.NewRequest(http.MethodPost, "/api/agent/hello",
		strings.NewReader(`{"node_id":"`+nodeID+`","version":"test"}`))
	allowed.RemoteAddr = "198.51.100.10:1234"
	allowed.Header.Set("Content-Type", "application/json")
	allowed.Header.Set("Authorization", "Bearer "+nodeToken)
	rec := serveReq(handler, allowed)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed source status = %d (%s)", rec.Code, rec.Body.String())
	}
	n, ok = st.Node(nodeID)
	if !ok || n.TokenLastUsedAt.IsZero() {
		t.Fatalf("allowed source did not touch token timestamp: ok=%v node=%+v", ok, n)
	}

	nodes := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, csrf)
	defer nodes.Body.Close()
	var views []struct {
		ID                   string   `json:"id"`
		AgentSourceAllowlist []string `json:"agent_source_allowlist"`
	}
	if err := json.NewDecoder(nodes.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		if view.ID == nodeID {
			if len(view.AgentSourceAllowlist) != 1 || view.AgentSourceAllowlist[0] != "198.51.100.10/32" {
				t.Fatalf("node view did not expose normalized allowlist: %+v", view.AgentSourceAllowlist)
			}
			return
		}
	}
	t.Fatalf("node %q missing from node views: %+v", nodeID, views)
}

func TestAgentSourceAllowlistCanBeSetAtEnrollment(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token", `{
		"node_id":"node-source-bound",
		"name":"Source Bound",
		"agent_source_allowlist":["198.51.100.10/32"]
	}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll with allowlist status = %d", res.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	denied := httptest.NewRequest(http.MethodPost, "/api/agent/hello",
		strings.NewReader(`{"node_id":"node-source-bound","version":"test"}`))
	denied.RemoteAddr = "203.0.113.20:1234"
	denied.Header.Set("Content-Type", "application/json")
	denied.Header.Set("Authorization", "Bearer "+out.Token)
	if rec := serveReq(handler, denied); rec.Code != http.StatusUnauthorized {
		t.Fatalf("enrolled allowlist did not deny first wrong-source auth: %d (%s)", rec.Code, rec.Body.String())
	}

	allowed := httptest.NewRequest(http.MethodPost, "/api/agent/hello",
		strings.NewReader(`{"node_id":"node-source-bound","version":"test"}`))
	allowed.RemoteAddr = "198.51.100.10:1234"
	allowed.Header.Set("Content-Type", "application/json")
	allowed.Header.Set("Authorization", "Bearer "+out.Token)
	if rec := serveReq(handler, allowed); rec.Code != http.StatusOK {
		t.Fatalf("enrolled allowlist denied allowed first source: %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAgentSourceAllowlistHonorsTrustedProxyHeaders(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, TrustProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	update := doJSON(t, handler, http.MethodPost, "/api/nodes/update", `{
		"node_id":"`+nodeID+`",
		"name":"Node A",
		"agent_source_allowlist":["198.51.100.10"]
	}`, cookies, csrf)
	update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("set allowlist status = %d", update.StatusCode)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/agent/hello",
		strings.NewReader(`{"node_id":"`+nodeID+`","version":"test"}`))
	req.RemoteAddr = "203.0.113.20:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+nodeToken)
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 203.0.113.1")
	rec := serveReq(handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trusted proxy source status = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAgentSourceAllowlistRejectsInvalidEntries(t *testing.T) {
	if _, err := normalizeAgentSourceAllowlist([]string{"198.51.100.10", "198.51.100.0/24"}); err != nil {
		t.Fatalf("valid allowlist rejected: %v", err)
	}
	for _, value := range []string{"not-an-ip", "198.51.100.0/not-bits", "https://example.com"} {
		if _, err := normalizeAgentSourceAllowlist([]string{value}); err == nil {
			t.Fatalf("invalid allowlist entry %q accepted", value)
		}
	}
	tooMany := make([]string, 0, maxAgentSourceAllowlistEntries+1)
	for i := 0; i <= maxAgentSourceAllowlistEntries; i++ {
		tooMany = append(tooMany, fmt.Sprintf("198.51.100.%d", i))
	}
	if _, err := normalizeAgentSourceAllowlist(tooMany); err == nil {
		t.Fatal("oversized allowlist accepted")
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
		{name: "proxy usage", path: "/api/agent/proxy-usage", body: `{"node_id":"` + nodeID + `","token":"` + nodeToken + `","snapshot":{"core_uptime_sec":1,"user_bytes":{}}}`},
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

func TestAgentJSONDecoderAllowsUnknownFieldsButRejectsTrailingValues(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	unknown := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello",
		`{"node_id":"`+nodeID+`","version":"test","future_agent_field":{"ok":true}}`, nodeToken)
	if unknown.Code != http.StatusOK {
		t.Fatalf("agent endpoints must tolerate unknown forward-compatible fields, got %d (%s)", unknown.Code, unknown.Body.String())
	}

	trailing := doAgentRaw(t, handler, http.MethodPost, "/api/agent/event",
		`{"node_id":"`+nodeID+`","kind":"agent.test","message":"ok"} {}`, nodeToken)
	if trailing.Code != http.StatusBadRequest {
		t.Fatalf("agent decoder must reject trailing JSON values, got %d (%s)", trailing.Code, trailing.Body.String())
	}
	if code := errorCodeFromRecorder(t, trailing); code != model.APIErrorBadRequest {
		t.Fatalf("expected bad_request for trailing JSON, got %q", code)
	}
}

func TestAgentHostFactsAreStoredAsSanitizedTelemetry(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	body := `{
		"node_id":"` + nodeID + `",
		"version":"test",
		"host_facts":{
			"hostname":"node-a\ncontrol",
			"os":"linux",
			"platform":"debian",
			"platform_version":"12",
			"kernel_version":"6.8.0-test",
			"arch":"amd64",
			"cpu_cores":4,
			"cpu_model":"Example CPU",
			"memory_total":8589934592,
			"swap_total":1099511627776,
			"virtualization":"kvm"
		}
	}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", body, nodeToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("hello with host facts failed: %d (%s)", rec.Code, rec.Body.String())
	}

	list := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, "")
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list nodes failed: %d", list.StatusCode)
	}
	var nodes []struct {
		ID        string          `json:"id"`
		HostFacts model.HostFacts `json:"host_facts"`
	}
	if err := json.NewDecoder(list.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != nodeID {
		t.Fatalf("unexpected nodes: %+v", nodes)
	}
	facts := nodes[0].HostFacts
	if facts.Hostname != "node-acontrol" {
		t.Fatalf("hostname should be control-char sanitized, got %q", facts.Hostname)
	}
	if facts.OS != "linux" || facts.Arch != "amd64" || facts.CPUCores != 4 || facts.MemoryTotal != 8589934592 {
		t.Fatalf("host facts not stored: %+v", facts)
	}
	if facts.ReportedAt.IsZero() {
		t.Fatal("server must stamp reported_at")
	}
}

func TestAgentRuntimeReportsTaskSandboxProfile(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)

	body := `{
		"node_id":"` + nodeID + `",
		"version":"test",
		"metrics":{},
		"agent_runtime":{
			"allow_exec":true,
			"allow_root_exec":false,
			"task_sandbox":" linux-rlimit-process-group ",
			"task_sandbox_features":["timeout","", "rlimit-cpu", "timeout", "minimal-env"],
			"task_sandbox_warning":" task scripts run as root "
		}
	}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", body, nodeToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics with runtime failed: %d (%s)", rec.Code, rec.Body.String())
	}

	list := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, "")
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list nodes failed: %d", list.StatusCode)
	}
	var nodes []struct {
		ID           string `json:"id"`
		AgentRuntime struct {
			AllowExec           bool     `json:"allow_exec"`
			TaskSandbox         string   `json:"task_sandbox"`
			TaskSandboxFeatures []string `json:"task_sandbox_features"`
			TaskSandboxWarning  string   `json:"task_sandbox_warning"`
		} `json:"agent_runtime"`
	}
	if err := json.NewDecoder(list.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != nodeID {
		t.Fatalf("unexpected nodes: %+v", nodes)
	}
	runtime := nodes[0].AgentRuntime
	if !runtime.AllowExec || runtime.TaskSandbox != "linux-rlimit-process-group" {
		t.Fatalf("runtime sandbox fields not stored: %+v", runtime)
	}
	wantFeatures := []string{"minimal-env", "rlimit-cpu", "timeout"}
	if !reflect.DeepEqual(runtime.TaskSandboxFeatures, wantFeatures) {
		t.Fatalf("features = %+v, want %+v", runtime.TaskSandboxFeatures, wantFeatures)
	}
	if runtime.TaskSandboxWarning != "task scripts run as root" {
		t.Fatalf("warning not trimmed: %q", runtime.TaskSandboxWarning)
	}
}

func TestNormalizeAgentRuntimeConfigBoundsTaskSandboxFields(t *testing.T) {
	truncatedFeature := strings.Repeat("x", maxAgentRuntimeFeature)
	features := []string{"timeout", " timeout ", "", "rlimit-cpu\ncontrol", strings.Repeat("x", maxAgentRuntimeFeature+32)}
	for i := 0; i < maxAgentRuntimeFeatureCount+4; i++ {
		features = append(features, fmt.Sprintf("feature-%02d", i))
	}

	got := normalizeAgentRuntimeConfig(agentRuntimeConfig{
		TaskSandbox:         " " + strings.Repeat("s", maxAgentRuntimeField+32) + "\n",
		TaskSandboxFeatures: features,
		TaskSandboxWarning:  strings.Repeat("w", maxAgentRuntimeWarning+32),
	}, time.Now())

	if len(got.TaskSandbox) != maxAgentRuntimeField {
		t.Fatalf("sandbox field should be clamped to %d bytes, got %d", maxAgentRuntimeField, len(got.TaskSandbox))
	}
	if len(got.TaskSandboxWarning) != maxAgentRuntimeWarning {
		t.Fatalf("sandbox warning should be clamped to %d bytes, got %d", maxAgentRuntimeWarning, len(got.TaskSandboxWarning))
	}
	if len(got.TaskSandboxFeatures) > maxAgentRuntimeFeatureCount {
		t.Fatalf("feature list should be capped at %d entries, got %d", maxAgentRuntimeFeatureCount, len(got.TaskSandboxFeatures))
	}
	if !stringSliceContains(got.TaskSandboxFeatures, "rlimit-cpucontrol") ||
		!stringSliceContains(got.TaskSandboxFeatures, "timeout") ||
		!stringSliceContains(got.TaskSandboxFeatures, truncatedFeature) {
		t.Fatalf("features should be sanitized and deduped, got %+v", got.TaskSandboxFeatures)
	}
	for _, feature := range got.TaskSandboxFeatures {
		if len(feature) > maxAgentRuntimeFeature || strings.ContainsAny(feature, "\n\r\t") {
			t.Fatalf("feature should be printable and capped, got %q", feature)
		}
	}
}

func TestNormalizeHostFactsDropsAbsurdValues(t *testing.T) {
	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	tooLongCPU := strings.Repeat("x", maxHostFactLong+32)

	got, ok := normalizeHostFacts(model.HostFacts{
		Hostname:    "node-a\ncontrol",
		OS:          "linux",
		Arch:        "amd64",
		CPUCores:    maxHostCPUCores + 1,
		CPUModel:    tooLongCPU,
		MemoryTotal: maxHostMemory + 1,
		SwapTotal:   maxHostMemory + 1,
		BootTime:    now.Add(10 * time.Minute),
		ReportedAt:  now.Add(-time.Hour),
	}, now)
	if !ok {
		t.Fatal("non-empty host facts should normalize")
	}
	if got.Hostname != "node-acontrol" {
		t.Fatalf("control characters should be stripped, got %q", got.Hostname)
	}
	if len(got.CPUModel) != maxHostFactLong {
		t.Fatalf("CPU model should be clamped to %d bytes, got %d", maxHostFactLong, len(got.CPUModel))
	}
	if got.CPUCores != 0 || got.MemoryTotal != 0 || got.SwapTotal != 0 {
		t.Fatalf("absurd numeric values should be dropped, got cores=%d mem=%d swap=%d", got.CPUCores, got.MemoryTotal, got.SwapTotal)
	}
	if !got.BootTime.IsZero() {
		t.Fatalf("future boot time should be dropped, got %s", got.BootTime)
	}
	if !got.ReportedAt.Equal(now) {
		t.Fatalf("reported_at must be server-stamped, got %s", got.ReportedAt)
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
		ID   string `json:"id"`
		Plan string `json:"plan"`
	}
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	bodies := []string{
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})),
		`{"approval_id":"` + approval.ID + `","queue_apply":true}`,
	}
	for i, body := range bodies {
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
