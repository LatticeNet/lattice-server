package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const agentUpdateTestSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func seedAgentUpdateNode(t *testing.T, st interface {
	UpsertNode(model.Node) error
}) {
	t.Helper()
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.1.0"}); err != nil {
		t.Fatal(err)
	}
}

func TestAgentUpdatePolicyPlanAndQueue(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	bad := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates", `{
		"node_id":"node-a",
		"enabled":true,
		"target_version":"0.2.0",
		"binary_url":"http://example.com/lattice-agent",
		"sha256":"`+agentUpdateTestSHA+`"
	}`, cookies, csrf)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("http binary URL must be rejected, got %d", bad.StatusCode)
	}
	bad.Body.Close()

	save := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates", `{
		"node_id":"node-a",
		"enabled":true,
		"auto_plan":true,
		"target_version":"0.2.0",
		"binary_url":"https://downloads.example.com/lattice-agent-linux-amd64",
		"sha256":"`+agentUpdateTestSHA+`",
		"install_path":"/usr/local/bin/lattice-agent",
		"service_name":"lattice-agent.service"
	}`, cookies, csrf)
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save policy failed: %d", save.StatusCode)
	}
	save.Body.Close()

	plan := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan", `{"node_id":"node-a"}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan update failed: %d", plan.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	plan.Body.Close()
	if approval.Plugin != agentUpdatePlugin || approval.Action != agentUpdateAction || approval.NodeID != "node-a" {
		t.Fatalf("bad approval view: %+v", approval)
	}
	for _, want := range []string{"target_version: 0.2.0", "sha256: " + agentUpdateTestSHA, "service restart is delayed"} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("approval plan missing %q:\n%s", want, approval.Plan)
		}
	}

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})),
		cookies, csrf)
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve update failed: %d", approve.StatusCode)
	}
	approve.Body.Close()
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("expected one update task, got %+v", tasks)
	}
	if tasks[0].TimeoutSec != 300 {
		t.Fatalf("agent update should get a longer download timeout, got %d", tasks[0].TimeoutSec)
	}
	script := tasks[0].Script
	for _, want := range []string{
		"curl -fsSL --proto '=https' --tlsv1.2",
		"EXPECT_SHA='" + agentUpdateTestSHA + "'",
		"CANDIDATE_VERSION=$(\"$CANDIDATE\" -version)",
		"version mismatch expected=$TARGET_VERSION actual=$CANDIDATE_VERSION",
		"lattice-agent-delayed-restart",
		"systemctl restart \"$SERVICE\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("update script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "sh -c") {
		t.Fatalf("update script must not use nested shell command strings:\n%s", script)
	}
}

func TestAgentUpdateAutoPlanDoesNotDuplicatePendingApproval(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	srv.evaluateAgentUpdatePolicies(now)
	srv.evaluateAgentUpdatePolicies(now.Add(time.Hour))
	approvals := st.Approvals()
	if len(approvals) != 1 {
		t.Fatalf("auto plan should create exactly one pending approval, got %+v", approvals)
	}
	approval := approvals[0]
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	srv.evaluateAgentUpdatePolicies(now.Add(2 * time.Hour))
	approvals = st.Approvals()
	if len(approvals) != 1 {
		t.Fatalf("auto plan should not duplicate an approved-but-not-applied update, got %+v", approvals)
	}
	policy, ok := st.AgentUpdatePolicy("node-a")
	if !ok || policy.LastPlannedVersion != "0.2.0" || policy.LastPlannedAt.IsZero() {
		t.Fatalf("policy planning metadata not updated: ok=%v policy=%+v", ok, policy)
	}
}

func TestOfficialAgentReleaseHelpers(t *testing.T) {
	target, err := normalizeOfficialAgentTarget("")
	if err != nil || target != agentReleaseLatest {
		t.Fatalf("empty official target = %q, %v", target, err)
	}
	target, err = normalizeOfficialAgentTarget("v0.2.2")
	if err != nil || target != "0.2.2" {
		t.Fatalf("v-prefixed official target = %q, %v", target, err)
	}
	if _, err := normalizeOfficialAgentTarget("../bad"); err == nil {
		t.Fatal("invalid official target should fail")
	}

	artifact, err := agentArtifactForNode(model.Node{HostFacts: model.HostFacts{OS: "linux", Arch: "x86_64"}})
	if err != nil || artifact != "lattice-agent-linux-amd64" {
		t.Fatalf("linux/x86_64 artifact = %q, %v", artifact, err)
	}
	artifact, err = agentArtifactForNode(model.Node{HostFacts: model.HostFacts{Platform: "debian", Arch: "aarch64"}})
	if err != nil || artifact != "lattice-agent-linux-arm64" {
		t.Fatalf("fallback linux/aarch64 artifact = %q, %v", artifact, err)
	}

	sha, ok := shaFromSums(agentUpdateTestSHA+"  lattice-agent-linux-amd64\n", "lattice-agent-linux-amd64")
	if !ok || sha != agentUpdateTestSHA {
		t.Fatalf("shaFromSums = %q, %v", sha, ok)
	}
}

func TestAgentUpdateFailureClosesApprovalAndAllowsReplan(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	approval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "manual", now)
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := srv.handleAgentUpdateTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-result", nil), approval, model.TaskResult{
		NodeID:     "node-a",
		ExitCode:   1,
		Stderr:     "download failed",
		FinishedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	failedApproval, ok := st.Approval(approval.ID)
	if !ok || failedApproval.Status != model.ApprovalRejected {
		t.Fatalf("failed update should close approval as rejected: ok=%v approval=%+v", ok, failedApproval)
	}
	policy, ok := st.AgentUpdatePolicy("node-a")
	if !ok || !strings.Contains(policy.LastError, "download failed") {
		t.Fatalf("policy should retain bounded failure reason: ok=%v policy=%+v", ok, policy)
	}
	srv.evaluateAgentUpdatePolicies(now.Add(2 * time.Hour))
	approvals := st.Approvals()
	if len(approvals) != 2 {
		t.Fatalf("a rejected update should allow a fresh auto-plan, got %+v", approvals)
	}
	pending := 0
	for _, approval := range approvals {
		if approval.Status == model.ApprovalPending {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("expected exactly one fresh pending approval after failure, got %+v", approvals)
	}
}

func TestAgentUpdateApproveRequiresCurrentPolicy(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)
	saveAgentUpdatePolicy(t, handler, cookies, csrf, "0.2.0")

	plan := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan", `{"node_id":"node-a"}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan update failed: %d", plan.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	plan.Body.Close()

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})),
		cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusConflict {
		t.Fatalf("stale agent update approval should require re-plan, got %d", approve.StatusCode)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("stale update approval queued tasks: %+v", st.Tasks())
	}
}

func saveAgentUpdatePolicy(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, version string) {
	t.Helper()
	save := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates", `{
		"node_id":"node-a",
		"enabled":true,
		"auto_plan":true,
		"target_version":"`+version+`",
		"binary_url":"https://downloads.example.com/lattice-agent-linux-amd64",
		"sha256":"`+agentUpdateTestSHA+`",
		"install_path":"/usr/local/bin/lattice-agent",
		"service_name":"lattice-agent.service"
	}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save policy %s failed: %d", version, save.StatusCode)
	}
}
