package server

import (
	"encoding/json"
	"errors"
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
		"wget --https-only -qO \"$CANDIDATE\" \"$URL\"",
		"EXPECT_SHA='" + agentUpdateTestSHA + "'",
		"RUNNING_AGENT=$(readlink -f \"/proc/$PPID/exe\"",
		"RUNNING_SERVICE=$(sed -n 's#.*system\\.slice/",
		"effective target=$TARGET service=$SERVICE",
		"CANDIDATE_VERSION=$(\"$CANDIDATE\" -version)",
		"version mismatch expected=$TARGET_VERSION actual=$CANDIDATE_VERSION",
		"service $SERVICE not found after installing $TARGET",
		"systemctl --no-legend list-unit-files \"$SERVICE\"",
		"grep -Fxq \"$SERVICE\"",
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
	if strings.Contains(script, "list-unit-files \"$SERVICE\" 2>/dev/null | grep -q .") {
		t.Fatalf("update script must match the service unit exactly:\n%s", script)
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

func TestNormalizeAgentUpdateURLRejectsSecretBearingURLs(t *testing.T) {
	cases := []string{
		"https://downloads.example.com/lattice-agent?token=secret",
		"https://downloads.example.com/lattice-agent?",
		"https://user:pass@downloads.example.com/lattice-agent",
		"https://downloads.example.com/lattice-agent#fragment",
	}
	for _, raw := range cases {
		if _, err := normalizeAgentUpdateURL(raw); err == nil {
			t.Fatalf("normalizeAgentUpdateURL(%q) should reject secret-bearing URL parts", raw)
		}
	}
}

func TestFetchAgentReleaseTextRejectsOversizedMetadata(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	metadata := strings.Repeat("x", agentReleaseMetadataLimit+1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(metadata))
	}))
	defer upstream.Close()

	_, err := srv.fetchAgentReleaseText(upstream.URL)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("oversized release metadata should be rejected, got %v", err)
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
	if !strings.Contains(failedApproval.Reason, "download failed") {
		t.Fatalf("failed update approval should expose failure reason, got %q", failedApproval.Reason)
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
	var apiErr model.APIErrorResponse
	if err := json.NewDecoder(approve.Body).Decode(&apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != model.APIErrorApprovalStale {
		t.Fatalf("stale agent update approval code = %q want %q", apiErr.Error.Code, model.APIErrorApprovalStale)
	}
	stale, ok := st.Approval(approval.ID)
	if !ok || stale.Status != model.ApprovalRejected {
		t.Fatalf("stale agent update approval should be closed as rejected: ok=%v approval=%+v", ok, stale)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("stale update approval queued tasks: %+v", st.Tasks())
	}
}

func TestAgentUpdateApprovalsListRejectsHistoricalStalePendingApproval(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "auto", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    strings.Repeat("a", 64), InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list approvals failed: %d", list.StatusCode)
	}
	var views []struct {
		approvalView
		Reason    string `json:"reason"`
		Stale     bool   `json:"stale"`
		StaleCode string `json:"stale_code"`
	}
	if err := json.NewDecoder(list.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("expected one approval view, got %+v", views)
	}
	if views[0].ID != approval.ID || views[0].Status != model.ApprovalRejected {
		t.Fatalf("historical stale agent update approval should be listed as rejected: %+v", views[0])
	}
	if !strings.Contains(views[0].Reason, "policy changed") || !strings.Contains(views[0].Reason, "re-plan") {
		t.Fatalf("historical stale agent update approval should expose rejection reason, got %q", views[0].Reason)
	}
	if !views[0].Stale || views[0].StaleCode != agentUpdateApprovalStaleCode {
		t.Fatalf("historical stale agent update approval should expose structured stale metadata, got stale=%v code=%q", views[0].Stale, views[0].StaleCode)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalRejected {
		t.Fatalf("historical stale agent update approval should be persisted rejected: ok=%v approval=%+v", ok, stored)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("stale update approval list cleanup queued tasks: %+v", st.Tasks())
	}
}

func TestAgentUpdateApprovalsListRejectsHistoricalLatestApprovalWithDifferentResolvedTarget(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID:             "node-a",
		Enabled:            true,
		AutoPlan:           true,
		TargetVersion:      agentReleaseLatest,
		LastPlannedVersion: "0.3.0",
		InstallPath:        defaultAgentInstallPath,
		ServiceName:        defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	payload := agentUpdatePayload{
		NodeID:        "node-a",
		TargetVersion: "0.2.0",
		BinaryURL:     "https://github.com/LatticeNet/lattice-node-agent/releases/download/v0.2.0/lattice-agent-linux-amd64",
		SHA256:        agentUpdateTestSHA,
		InstallPath:   defaultAgentInstallPath,
		ServiceName:   defaultAgentServiceName,
	}
	approval := model.Approval{
		ID:        "approval-latest-stale",
		NodeID:    "node-a",
		Plugin:    agentUpdatePlugin,
		Action:    agentUpdateApprovalAction(payload),
		Plan:      renderAgentUpdatePlan(model.Node{ID: "node-a", AgentVersion: "0.1.0"}, payload, "auto"),
		Status:    model.ApprovalPending,
		CreatedAt: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list approvals failed: %d", list.StatusCode)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalRejected {
		t.Fatalf("historical latest approval should be rejected after resolved target changes: ok=%v approval=%+v", ok, stored)
	}
	if !strings.Contains(stored.Reason, "policy changed") || !strings.Contains(stored.Reason, "re-plan") {
		t.Fatalf("historical latest approval should expose re-plan reason, got %q", stored.Reason)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("stale latest approval list cleanup queued tasks: %+v", st.Tasks())
	}
}

func TestAgentUpdateApprovalsListRejectsHistoricalStaleApprovedWithoutActiveTask(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "manual", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    strings.Repeat("a", 64), InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list approvals failed: %d", list.StatusCode)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalRejected {
		t.Fatalf("approved stale update without active task should be rejected: ok=%v approval=%+v", ok, stored)
	}
	if !strings.Contains(stored.Reason, "policy changed") || !strings.Contains(stored.Reason, "re-plan") {
		t.Fatalf("approved stale update should expose re-plan reason, got %q", stored.Reason)
	}
}

func TestAgentUpdateApprovalsListKeepsApprovedWithActiveTask(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "manual", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-active-update", ApprovalID: approval.ID, Targets: []string{"node-a"}, Status: model.TaskQueued}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    strings.Repeat("a", 64), InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list approvals failed: %d", list.StatusCode)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("approved update with active task should remain in-flight: ok=%v approval=%+v", ok, stored)
	}
}

func TestAgentUpdatePolicySaveRejectsPendingApproval(t *testing.T) {
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

	saveAgentUpdatePolicy(t, handler, cookies, csrf, "0.3.0")

	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalRejected {
		t.Fatalf("policy save should reject stale pending approval: ok=%v approval=%+v", ok, stored)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("policy save queued tasks: %+v", st.Tasks())
	}
}

func TestAgentUpdatePolicySaveRejectsApprovedApprovalWithoutActiveTask(t *testing.T) {
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
	stored, ok := st.Approval(approval.ID)
	if !ok {
		t.Fatalf("planned approval not stored: %s", approval.ID)
	}
	stored.Status = model.ApprovalApproved
	if err := st.UpsertApproval(stored); err != nil {
		t.Fatal(err)
	}

	saveAgentUpdatePolicy(t, handler, cookies, csrf, "0.3.0")

	stored, ok = st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalRejected {
		t.Fatalf("policy save should reject stale approved-only approval: ok=%v approval=%+v", ok, stored)
	}
	if !strings.Contains(stored.Reason, "policy changed") || !strings.Contains(stored.Reason, "re-plan") {
		t.Fatalf("stale approved-only approval should expose re-plan reason, got %q", stored.Reason)
	}
}

func TestAgentUpdatePolicySaveKeepsApprovedApprovalWithActiveTask(t *testing.T) {
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
	stored, ok := st.Approval(approval.ID)
	if !ok {
		t.Fatalf("planned approval not stored: %s", approval.ID)
	}
	stored.Status = model.ApprovalApproved
	if err := st.UpsertApproval(stored); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-active-policy-save", ApprovalID: approval.ID, Targets: []string{"node-a"}, Status: model.TaskQueued}); err != nil {
		t.Fatal(err)
	}

	saveAgentUpdatePolicy(t, handler, cookies, csrf, "0.3.0")

	stored, ok = st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("policy save should keep approved approval with active task: ok=%v approval=%+v", ok, stored)
	}
}

func TestAgentUpdatePolicyDeleteRejectsPendingApproval(t *testing.T) {
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

	del := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/delete", `{"node_id":"node-a"}`, cookies, csrf)
	defer del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete policy failed: %d", del.StatusCode)
	}

	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalRejected {
		t.Fatalf("policy delete should reject stale pending approval: ok=%v approval=%+v", ok, stored)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("policy delete queued tasks: %+v", st.Tasks())
	}
}

func TestAgentUpdateNewPlanRejectsSupersededPendingApproval(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	oldApproval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "auto", now)
	if err != nil {
		t.Fatal(err)
	}

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    strings.Repeat("a", 64), InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	newApproval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "auto", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if oldApproval.ID == newApproval.ID {
		t.Fatal("expected a distinct replacement approval")
	}

	oldStored, ok := st.Approval(oldApproval.ID)
	if !ok || oldStored.Status != model.ApprovalRejected {
		t.Fatalf("superseded pending approval should be rejected: ok=%v approval=%+v", ok, oldStored)
	}
	newStored, ok := st.Approval(newApproval.ID)
	if !ok || newStored.Status != model.ApprovalPending {
		t.Fatalf("replacement approval should stay pending: ok=%v approval=%+v", ok, newStored)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("replanning must not queue tasks before approval: %+v", st.Tasks())
	}
}

func TestAgentUpdateNoopRejectsPendingApprovalForCurrentTarget(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "auto", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.0"}); err != nil {
		t.Fatal(err)
	}

	_, err = srv.createAgentUpdateApproval("node-a", "", false, "auto", now.Add(time.Minute))
	if !errors.Is(err, errAgentUpdateNoop) {
		t.Fatalf("current target should be a noop, got %v", err)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalRejected {
		t.Fatalf("noop target should close pending update approval: ok=%v approval=%+v", ok, stored)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("noop update queued tasks: %+v", st.Tasks())
	}
}

func TestAgentUpdatePlanNoopReturnsStableCode(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)
	saveAgentUpdatePolicy(t, handler, cookies, csrf, "0.2.0")
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.0"}); err != nil {
		t.Fatal(err)
	}

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan",
		`{"node_id":"node-a"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("noop plan should return 409, got %d", res.StatusCode)
	}
	var apiErr model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != model.APIErrorAgentUpdateNoop {
		t.Fatalf("noop plan code = %q want %q", apiErr.Error.Code, model.APIErrorAgentUpdateNoop)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("noop planning must not queue tasks: %+v", st.Tasks())
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
