package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const agentUpdateTestSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func seedAgentUpdateNode(t *testing.T, st interface {
	UpsertNode(model.Node) error
}) {
	t.Helper()
	// Beating: auto-planning is for a node that can actually receive the plan,
	// and the sweep now skips ones that cannot.
	if err := st.UpsertNode(model.Node{
		ID: "node-a", Name: "Node A", AgentVersion: "0.1.0",
		Online: true, LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

// A machine that is switched off would otherwise collect one auto plan per
// release, each pending against a node with nothing to apply it, and each
// naming a version that may be superseded before the node returns.
func TestAgentUpdateAutoPlanSkipsANodeThatCannotReceiveIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		node model.Node
		want int
	}{
		{"beating", model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.1.0", Online: true, LastSeen: time.Now().UTC()}, 1},
		{"went quiet", model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.1.0", LastSeen: time.Now().UTC().Add(-30 * 24 * time.Hour)}, 0},
		{"never reported", model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.1.0"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, st := newInventoryServer(t)
			if err := st.UpsertNode(tc.node); err != nil {
				t.Fatal(err)
			}
			if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
				NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
				BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
				SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
			}); err != nil {
				t.Fatal(err)
			}
			srv.evaluateAgentUpdatePolicies(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
			if got := len(st.Approvals()); got != tc.want {
				t.Fatalf("%s: auto plans = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// Deferring is the automatic path only. An operator who asks for a plan on a
// node that is down still gets one: they may be about to bring it up.
func TestAgentUpdateManualPlanStillWorksForAQuietNode(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{
		ID: "node-a", Name: "Node A", AgentVersion: "0.1.0",
		LastSeen: time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "operator", false, "manual", time.Now().UTC()); err != nil {
		t.Fatalf("manual plan for a quiet node must still be allowed: %v", err)
	}
	if got := len(st.Approvals()); got != 1 {
		t.Fatalf("manual plans = %d, want 1", got)
	}
}

func TestCompareAgentVersionsPrereleaseOrdering(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"0.3.3", "0.3.4-alpha.1", -1, true},
		{"v0.3.4-alpha.1", "0.3.4-beta.1", -1, true},
		{"0.3.4-beta.2", "0.3.4-rc.1", -1, true},
		{"0.3.4-rc.9", "0.3.4", -1, true},
		{"0.3.4-alpha.2", "0.3.4-alpha.1", 1, true},
		{"0.3", "0.3.0", 0, false},
		{"0.3.4-preview.1", "0.3.4", 0, false},
		{" 0.3.4", "0.3.4", 0, false},
		{"0.3.4 ", "0.3.4", 0, false},
	}
	for _, tc := range tests {
		got, ok := compareAgentVersions(tc.a, tc.b)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("compare(%q,%q)=(%d,%v), want (%d,%v)", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
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
	for _, want := range []string{
		"target_version: 0.2.0",
		"sha256: " + agentUpdateTestSHA,
		"service restart is delayed",
		"default/legacy install targets follow the running lattice-agent path",
	} {
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
	// 600, not 900. This assertion used to demand 900 and was wrong in the way
	// that matters: the agent's task executor treats anything above ten minutes
	// as out of range and substitutes its 30 second default, so 900 gave slow
	// nodes less time than asking for nothing would have. The test passed while
	// the fleet could not update.
	if tasks[0].TimeoutSec != 600 {
		t.Fatalf("agent update should get the extended download timeout, at or under the agent's "+
			"ten minute bound so it is honoured rather than replaced by the 30s default, got %d",
			tasks[0].TimeoutSec)
	}
	script := tasks[0].Script
	for _, want := range []string{
		"curl -fsSL --proto '=https' --tlsv1.2",
		"wget --https-only -q --timeout=20 --tries=2 -O \"$CANDIDATE\" \"$URL\"",
		"EXPECT_SHA='" + agentUpdateTestSHA + "'",
		"RUNNING_AGENT=$(readlink -f \"/proc/$PPID/exe\"",
		"RUNNING_SERVICE=$(sed -n 's#.*system\\.slice/",
		"effective target=$TARGET service=$SERVICE",
		"systemd is required for managed agent updates",
		"systemd-run is required to schedule a verified delayed restart",
		"CANDIDATE_VERSION=$(\"$CANDIDATE\" -version)",
		"version mismatch expected=$TARGET_VERSION actual=$CANDIDATE_VERSION",
		"service $SERVICE not found before installing $TARGET",
		"systemctl --no-legend list-unit-files \"$SERVICE\"",
		"grep -Fxq \"$SERVICE\"",
		"RESTART_UNIT=\"lattice-agent-delayed-restart-$(date +%Y%m%d%H%M%S)-$$\"",
		"systemd-run --unit=\"$RESTART_UNIT\" --on-active=3s /bin/systemctl restart \"$SERVICE\"",
		"scheduled $SERVICE restart via $RESTART_UNIT",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("update script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "--unit=lattice-agent-delayed-restart --on-active=3s") {
		t.Fatalf("update script must not reuse a fixed transient restart unit:\n%s", script)
	}
	if strings.Contains(script, "sh -c") {
		t.Fatalf("update script must not use nested shell command strings:\n%s", script)
	}
	if strings.Contains(script, "list-unit-files \"$SERVICE\" 2>/dev/null | grep -q .") {
		t.Fatalf("update script must match the service unit exactly:\n%s", script)
	}
	systemdCheck := strings.Index(script, "systemd is required for managed agent updates")
	systemdRunCheck := strings.Index(script, "systemd-run is required to schedule a verified delayed restart")
	serviceCheck := strings.Index(script, "service $SERVICE not found before installing $TARGET")
	download := strings.Index(script, "curl -fsSL --proto '=https' --tlsv1.2")
	install := strings.Index(script, "install -m 0755 \"$CANDIDATE\" \"$TARGET.new\"")
	if systemdCheck < 0 || systemdRunCheck < 0 || serviceCheck < 0 || download < 0 || install < 0 {
		t.Fatalf("update script missing ordered safety checkpoints:\n%s", script)
	}
	if systemdCheck > download || systemdRunCheck > download {
		t.Fatalf("restart manager checks must happen before download:\n%s", script)
	}
	if serviceCheck > install {
		t.Fatalf("service existence check must happen before install:\n%s", script)
	}
	for _, forbidden := range []string{"restart $SERVICE manually", "sleep 3; systemctl restart"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("managed update script must not use unverified restart fallback %q:\n%s", forbidden, script)
		}
	}
}

func TestAgentUpdateApplyRequiresHeartbeatConfirmation(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	plan := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan", `{"node_id":"node-a"}`, cookies, csrf)
	if plan.StatusCode != http.StatusOK {
		plan.Body.Close()
		t.Fatalf("plan update failed: %d", plan.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	plan.Body.Close()

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})),
		cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve update failed: %d", approve.StatusCode)
	}

	tasksRec := doAgentRaw(t, handler, http.MethodGet, "/api/agent/tasks?node_id=node-a", "", nodeToken)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease update task failed: %d %s", tasksRec.Code, tasksRec.Body.String())
	}
	var tasks []agentTaskView
	if err := json.NewDecoder(tasksRec.Body).Decode(&tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].LeaseID == "" {
		t.Fatalf("expected one leased update task, got %+v", tasks)
	}
	result := `{"node_id":"node-a","result":{"task_id":` + string(mustJSON(t, tasks[0].ID)) +
		`,"lease_id":` + string(mustJSON(t, tasks[0].LeaseID)) + `,"exit_code":0,"stdout":"installed"}}`
	resultRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", result, nodeToken)
	if resultRec.Code != http.StatusOK {
		t.Fatalf("task result failed: %d %s", resultRec.Code, resultRec.Body.String())
	}

	awaiting, ok := st.Approval(approval.ID)
	if !ok || awaiting.Status != model.ApprovalApproved || !strings.Contains(awaiting.Reason, "awaiting agent version confirmation") {
		t.Fatalf("successful update task should await heartbeat confirmation: ok=%v approval=%+v", ok, awaiting)
	}
	policy, ok := st.AgentUpdatePolicy("node-a")
	if !ok || policy.LastAppliedVersion != "" || !policy.LastAppliedAt.IsZero() || !strings.Contains(policy.LastError, "awaiting agent version confirmation") {
		t.Fatalf("policy should not be applied until target-version heartbeat: ok=%v policy=%+v", ok, policy)
	}

	hello := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"0.2.0"}`, nodeToken)
	if hello.Code != http.StatusOK {
		t.Fatalf("target-version heartbeat failed: %d %s", hello.Code, hello.Body.String())
	}
	confirmed, ok := st.Approval(approval.ID)
	if !ok || confirmed.Status != model.ApprovalApplied || !strings.HasPrefix(confirmed.Reason, "Node agent upgrade") || !strings.HasSuffix(confirmed.Reason, "confirmed by the node's report: agent version 0.2.0") {
		t.Fatalf("target-version heartbeat should confirm update approval: ok=%v approval=%+v", ok, confirmed)
	}
	policy, ok = st.AgentUpdatePolicy("node-a")
	if !ok || policy.LastAppliedVersion != "0.2.0" || policy.LastAppliedAt.IsZero() || policy.LastError != "" {
		t.Fatalf("target-version heartbeat should confirm update policy: ok=%v policy=%+v", ok, policy)
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

func TestAgentUpdateManualPlanReturnsExistingEquivalentApproval(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)
	saveAgentUpdatePolicy(t, handler, cookies, csrf, "0.2.0")

	first := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan", `{"node_id":"node-a"}`, cookies, csrf)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first plan failed: %d", first.StatusCode)
	}
	var firstApproval approvalView
	if err := json.NewDecoder(first.Body).Decode(&firstApproval); err != nil {
		t.Fatal(err)
	}
	first.Body.Close()

	second := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan", `{"node_id":"node-a"}`, cookies, csrf)
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second plan should return existing approval, got %d", second.StatusCode)
	}
	var secondApproval approvalView
	if err := json.NewDecoder(second.Body).Decode(&secondApproval); err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if secondApproval.ID != firstApproval.ID {
		t.Fatalf("second plan should reuse existing approval %s, got %s", firstApproval.ID, secondApproval.ID)
	}
	if approvals := st.Approvals(); len(approvals) != 1 {
		t.Fatalf("reusing existing approval should not create duplicates: %+v", approvals)
	}
}

func TestAgentUpdatePolicyDefaultsToNodeAgentInstallPath(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)

	policy, err := srv.normalizeAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID:        "node-a",
		Enabled:       true,
		AutoPlan:      true,
		TargetVersion: "0.2.0",
		BinaryURL:     "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:        agentUpdateTestSHA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.InstallPath != defaultAgentInstallPath {
		t.Fatalf("empty install_path should default to node-agent path %q, got %q", defaultAgentInstallPath, policy.InstallPath)
	}

	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID:        "node-a",
		Enabled:       true,
		TargetVersion: "0.2.0",
		BinaryURL:     "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:        agentUpdateTestSHA,
		InstallPath:   previousDefaultAgentInstallPath,
		ServiceName:   defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	payload, err := srv.agentUpdatePayloadForPolicy(model.Node{ID: "node-a", AgentVersion: "0.1.0"}, model.AgentUpdatePolicy{
		NodeID:        "node-a",
		Enabled:       true,
		TargetVersion: "0.2.0",
		BinaryURL:     "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:        agentUpdateTestSHA,
		InstallPath:   previousDefaultAgentInstallPath,
		ServiceName:   defaultAgentServiceName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload.InstallPath != defaultAgentInstallPath {
		t.Fatalf("previous default path should normalize to node-agent path %q, got %q", defaultAgentInstallPath, payload.InstallPath)
	}
}

func TestAgentUpdatePlanRejectsDowngradeTarget(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.8"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	saveAgentUpdatePolicy(t, handler, cookies, csrf, "0.2.7")

	plan := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusBadRequest {
		t.Fatalf("downgrade plan should be rejected, got %d", plan.StatusCode)
	}
	var apiErr model.APIErrorResponse
	if err := json.NewDecoder(plan.Body).Decode(&apiErr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(apiErr.Error.Message, "refusing to plan agent downgrade from 0.2.8 to 0.2.7") {
		t.Fatalf("downgrade rejection should name both versions, got %q", apiErr.Error.Message)
	}
	if approvals := st.Approvals(); len(approvals) != 0 {
		t.Fatalf("downgrade plan should not create approvals: %+v", approvals)
	}
}

func TestAgentUpdateCurrentVersionChangeSupersedesApproval(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.7"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.8",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}

	first, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first.Plan, "current_version: 0.2.7") {
		t.Fatalf("first plan should freeze current version:\n%s", first.Plan)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.2"}); err != nil {
		t.Fatal(err)
	}

	second, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", time.Date(2026, 7, 4, 10, 5, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatalf("current_version change should create a fresh approval, reused %s", first.ID)
	}
	if !strings.Contains(second.Plan, "current_version: 0.2.2") {
		t.Fatalf("second plan should show the new current version:\n%s", second.Plan)
	}
	stale, ok := st.Approval(first.ID)
	if !ok || stale.Status != model.ApprovalRejected {
		t.Fatalf("old approval should be rejected as stale: ok=%v approval=%+v", ok, stale)
	}
	if !strings.Contains(stale.Reason, "current_version planned=0.2.7 current=0.2.2") {
		t.Fatalf("stale reason should explain current_version change, got %q", stale.Reason)
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
	if _, err := agentArtifactForNode(model.Node{HostFacts: model.HostFacts{OS: "darwin", Arch: "arm64"}}); err == nil ||
		!strings.Contains(err.Error(), "manual-only") {
		t.Fatalf("darwin managed update should be rejected as manual-only, got %v", err)
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

func TestAgentUpdatePayloadRejectsPartialExplicitArtifactPolicy(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	node := model.Node{ID: "node-a", HostFacts: model.HostFacts{OS: "linux", Arch: "amd64"}}
	cases := []model.AgentUpdatePolicy{
		{
			NodeID:        "node-a",
			Enabled:       true,
			TargetVersion: "0.2.0",
			BinaryURL:     "https://downloads.example.com/lattice-agent-linux-amd64",
			InstallPath:   defaultAgentInstallPath,
			ServiceName:   defaultAgentServiceName,
		},
		{
			NodeID:        "node-a",
			Enabled:       true,
			TargetVersion: "0.2.0",
			SHA256:        agentUpdateTestSHA,
			InstallPath:   defaultAgentInstallPath,
			ServiceName:   defaultAgentServiceName,
		},
	}
	for _, policy := range cases {
		if _, err := srv.agentUpdatePayloadForPolicy(node, policy); err == nil || !strings.Contains(err.Error(), "binary_url and sha256 must be provided together") {
			t.Fatalf("partial explicit artifact policy should fail closed before official resolution, got %v", err)
		}
	}
}

func TestAgentUpdatePayloadRejectsNonLinuxManagedUpdates(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	node := model.Node{ID: "node-a", HostFacts: model.HostFacts{OS: "darwin", Arch: "arm64"}}
	policy := model.AgentUpdatePolicy{
		NodeID:        "node-a",
		Enabled:       true,
		TargetVersion: "0.2.0",
		BinaryURL:     "https://downloads.example.com/lattice-agent-darwin-arm64",
		SHA256:        agentUpdateTestSHA,
		InstallPath:   defaultAgentInstallPath,
		ServiceName:   defaultAgentServiceName,
	}
	if _, err := srv.agentUpdatePayloadForPolicy(node, policy); err == nil || !strings.Contains(err.Error(), "manual-only") {
		t.Fatalf("darwin managed update should be rejected before planning, got %v", err)
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

func TestFetchAgentReleaseTextCachesFailures(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	now := time.Date(2026, 7, 5, 14, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer upstream.Close()

	for i := 0; i < 2; i++ {
		if _, err := srv.fetchAgentReleaseText(upstream.URL); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("rate limited release metadata should fail with 403, got %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("release metadata failures should be cached briefly, got %d upstream calls", calls)
	}
	now = now.Add(agentReleaseErrorCacheTTL + time.Second)
	if _, err := srv.fetchAgentReleaseText(upstream.URL); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expired cached release metadata error should refetch and fail with 403, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expired release metadata failure cache should refetch, got %d upstream calls", calls)
	}
}

func TestLatestStableAgentReleaseTagSkipsPrereleases(t *testing.T) {
	tag, err := latestStableAgentReleaseTag(`[
		{"tag_name":"v0.3.3","draft":false,"prerelease":true},
		{"tag_name":"v0.3.2-alpha.2","draft":false,"prerelease":true},
		{"tag_name":"v0.2.8","draft":false,"prerelease":false}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v0.2.8" {
		t.Fatalf("latest stable tag = %q want v0.2.8", tag)
	}
}

func TestLatestStableAgentReleaseTagRejectsOnlyPrereleases(t *testing.T) {
	_, err := latestStableAgentReleaseTag(`[
		{"tag_name":"v0.3.3","draft":false,"prerelease":true},
		{"tag_name":"not-semver","draft":false,"prerelease":false},
		{"tag_name":"v0.2.9","draft":true,"prerelease":false}
	]`)
	if err == nil {
		t.Fatal("expected no stable v* release error")
	}
}

func TestAgentReleaseCandidatesExposeChannels(t *testing.T) {
	candidates, err := agentReleaseCandidates("LatticeNet/lattice-node-agent", `[
		{"tag_name":"v0.3.4-beta.1","draft":false,"prerelease":true},
		{"tag_name":"v0.3.3-alpha.2","draft":false,"prerelease":true},
		{"tag_name":"v0.3.2-alpha.1","draft":false,"prerelease":true},
		{"tag_name":"v0.2.8","draft":false,"prerelease":false},
		{"tag_name":"v0.2.7","draft":false,"prerelease":false},
		{"tag_name":"v0.2.9-rc.1","draft":true,"prerelease":true},
		{"tag_name":"not-semver","draft":false,"prerelease":false}
	]`, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 5 {
		t.Fatalf("candidates len = %d want 5: %+v", len(candidates), candidates)
	}
	want := []struct {
		version string
		channel string
		latest  bool
	}{
		{"0.3.4-beta.1", "beta", true},
		{"0.3.3-alpha.2", "alpha", true},
		{"0.3.2-alpha.1", "alpha", false},
		{"0.2.8", "stable", true},
		{"0.2.7", "stable", false},
	}
	for i, w := range want {
		got := candidates[i]
		if got.Version != w.version || got.Channel != w.channel || got.LatestForChannel != w.latest {
			t.Fatalf("candidate %d = %+v want version=%s channel=%s latest=%t", i, got, w.version, w.channel, w.latest)
		}
		if !strings.Contains(got.ReleaseURL, "/releases/tag/v"+w.version) {
			t.Fatalf("candidate %d release url = %q", i, got.ReleaseURL)
		}
	}
}

func TestAgentUpdateFailureReturnsApprovalToPending(t *testing.T) {
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", now)
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
		Error:      "exit status 1",
		Stdout:     "lattice agent update: downloading official binary",
		Stderr:     "download failed",
		FinishedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	failedApproval, ok := st.Approval(approval.ID)
	if !ok || failedApproval.Status != model.ApprovalPending {
		t.Fatalf("failed update must return the approval to pending for retry (execution failure is not a decision): ok=%v approval=%+v", ok, failedApproval)
	}
	if !strings.Contains(failedApproval.Reason, "execution failed") || !strings.Contains(failedApproval.Reason, "download failed") {
		t.Fatalf("failed update approval should expose failure reason, got %q", failedApproval.Reason)
	}
	if !strings.Contains(failedApproval.Reason, "error=exit status 1") || !strings.Contains(failedApproval.Reason, "exit_code=1") {
		t.Fatalf("failed update approval should expose error and exit code, got %q", failedApproval.Reason)
	}
	policy, ok := st.AgentUpdatePolicy("node-a")
	if !ok || !strings.Contains(policy.LastError, "download failed") || !strings.Contains(policy.LastError, "stdout=lattice agent update") {
		t.Fatalf("policy should retain bounded failure reason: ok=%v policy=%+v", ok, policy)
	}
	srv.evaluateAgentUpdatePolicies(now.Add(2 * time.Hour))
	approvals := st.Approvals()
	// The re-pended approval IS the retry vehicle: the auto-planner must dedup
	// against it (same node, same action payload) instead of stacking a second
	// pending card for the identical plan.
	if len(approvals) != 1 {
		t.Fatalf("re-planning must dedup against the re-pended failure, got %+v", approvals)
	}
	if approvals[0].Status != model.ApprovalPending || !strings.Contains(approvals[0].Reason, "execution failed") {
		t.Fatalf("the re-pended approval remains the single pending retry card, got %+v", approvals[0])
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
	if !strings.Contains(apiErr.Error.Message, "changed fields:") ||
		!strings.Contains(apiErr.Error.Message, "target_version planned=0.2.0 current=0.3.0") ||
		!strings.Contains(apiErr.Error.Message, "install_path planned=/usr/local/bin/lattice-agent current="+defaultAgentInstallPath) {
		t.Fatalf("stale agent update approval should explain changed fields, got %q", apiErr.Error.Message)
	}
	stale, ok := st.Approval(approval.ID)
	if !ok || stale.Status != model.ApprovalRejected {
		t.Fatalf("stale agent update approval should be closed as rejected: ok=%v approval=%+v", ok, stale)
	}
	if !strings.Contains(stale.Reason, "changed fields:") ||
		!strings.Contains(stale.Reason, "target_version planned=0.2.0 current=0.3.0") ||
		!strings.Contains(stale.Reason, "install_path planned=/usr/local/bin/lattice-agent current="+defaultAgentInstallPath) {
		t.Fatalf("stale agent update approval should persist changed fields, got %q", stale.Reason)
	}
	view := toApprovalView(stale)
	if !view.Stale || view.StaleCode != agentUpdateApprovalStaleCode {
		t.Fatalf("detailed stale reason should preserve stale metadata, got stale=%v code=%q", view.Stale, view.StaleCode)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("stale update approval queued tasks: %+v", st.Tasks())
	}
}

func TestAgentUpdatePayloadChangeSummaryNamesSHAChanges(t *testing.T) {
	planned := agentUpdatePayload{
		NodeID:        "node-a",
		TargetVersion: "0.2.7",
		BinaryURL:     "https://github.com/LatticeNet/lattice-node-agent/releases/download/v0.2.7/lattice-agent-linux-amd64",
		SHA256:        strings.Repeat("6", 64),
		InstallPath:   defaultAgentInstallPath,
		ServiceName:   defaultAgentServiceName,
	}
	current := planned
	current.SHA256 = strings.Repeat("5", 64)

	summary := agentUpdatePayloadChangeSummary(planned, current)
	if !strings.Contains(summary, "sha256 planned=6666666666666666... current=5555555555555555...") {
		t.Fatalf("sha256 change summary missing digest diff: %q", summary)
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
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
	if !strings.Contains(views[0].Reason, "target_version planned=0.2.0 current=0.3.0") ||
		!strings.Contains(views[0].Reason, "sha256 planned=0123456789abcdef... current=aaaaaaaaaaaaaaaa...") {
		t.Fatalf("historical stale agent update approval should expose changed fields, got %q", views[0].Reason)
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

func TestDismissStaleAgentUpdateApprovalHidesItFromDefaultList(t *testing.T) {
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
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

	dismiss := doJSON(t, handler, http.MethodPost, "/api/network/approvals/dismiss",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID})), cookies, csrf)
	defer dismiss.Body.Close()
	if dismiss.StatusCode != http.StatusOK {
		t.Fatalf("dismiss stale approval should succeed, got %d", dismiss.StatusCode)
	}
	var dismissed approvalView
	if err := json.NewDecoder(dismiss.Body).Decode(&dismissed); err != nil {
		t.Fatal(err)
	}
	if dismissed.ID != approval.ID || dismissed.Status != "dismissed" || !dismissed.Stale {
		t.Fatalf("dismiss response should mark stale approval dismissed, got %+v", dismissed)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != "dismissed" {
		t.Fatalf("dismiss should persist a tombstone without deleting approval: ok=%v approval=%+v", ok, stored)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list approvals failed: %d", list.StatusCode)
	}
	var visible []approvalView
	if err := json.NewDecoder(list.Body).Decode(&visible); err != nil {
		t.Fatal(err)
	}
	if len(visible) != 0 {
		t.Fatalf("dismissed stale approval should be hidden from default list, got %+v", visible)
	}

	withDismissed := doJSON(t, handler, http.MethodGet, "/api/network/approvals?include_dismissed=true", "", cookies, csrf)
	defer withDismissed.Body.Close()
	if withDismissed.StatusCode != http.StatusOK {
		t.Fatalf("list approvals with dismissed failed: %d", withDismissed.StatusCode)
	}
	var all []approvalView
	if err := json.NewDecoder(withDismissed.Body).Decode(&all); err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != approval.ID || all[0].Status != "dismissed" {
		t.Fatalf("include_dismissed should return dismissed approval, got %+v", all)
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
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
	if !strings.Contains(stored.Reason, "target_version planned=0.2.0 current=0.3.0") {
		t.Fatalf("policy save should record changed fields, got %q", stored.Reason)
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
	if !strings.Contains(stored.Reason, `policy "node-a" not found`) {
		t.Fatalf("policy delete should record missing policy detail, got %q", stored.Reason)
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
	oldApproval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", now)
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
	newApproval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", now.Add(time.Minute))
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	policy, ok := st.AgentUpdatePolicy("node-a")
	if !ok {
		t.Fatal("agent update policy missing")
	}
	policy.LastAppliedVersion = "0.1.9"
	policy.LastAppliedAt = now.Add(-time.Hour)
	policy.LastError = "error=exit status 1"
	if err := st.UpsertAgentUpdatePolicy(policy); err != nil {
		t.Fatal(err)
	}

	_, err = srv.createAgentUpdateApproval(context.Background(), "node-a", "", false, "auto", now.Add(time.Minute))
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
	policy, ok = st.AgentUpdatePolicy("node-a")
	if !ok || policy.LastError != "" || policy.LastAppliedVersion != "0.2.0" || !policy.LastAppliedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("noop target should mark policy satisfied: ok=%v policy=%+v", ok, policy)
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

// The update task runs inside the agent's rlimit shim (RLIMIT_FSIZE 8 MiB) and
// the release binary is larger — the fleet proved it on 2026-08-12 (SIGXFSZ,
// exit 153, on 18 nodes). The script must lift its inherited cap before the
// download; this works with the agents already deployed because tasks run as
// root and the limit is raised by the script itself.
func TestAgentUpdateApplyScriptLiftsFileSizeLimit(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	script, err := agentUpdateApplyScript(approval, srv.publicURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "ulimit -Hf unlimited") || !strings.Contains(script, "ulimit -Sf unlimited") {
		t.Fatalf("apply script must lift RLIMIT_FSIZE before the binary download:\n%s", script[:400])
	}
}

// The agent update timeout must stay within what the node will honour.
//
// The agent's task executor treats a timeout above ten minutes as out of range
// and falls back to its 30 second DEFAULT rather than clamping to the maximum.
// So a value chosen here to be generous silently becomes the least generous
// one possible, and every node too slow to download the binary in 30 seconds
// fails with "context deadline exceeded". That is not hypothetical: 900 was set
// to rescue a slow node and is what broke it, along with every other slow node
// in the fleet.
func TestAgentUpdateTimeoutStaysWithinTheAgentsAcceptedRange(t *testing.T) {
	const agentMaxAcceptedSec = 600 // ten minutes, the agent's upper bound

	got := approvalApplyTaskTimeoutSec(agentUpdatePlugin)
	if got > agentMaxAcceptedSec {
		t.Fatalf("an agent update timeout above %ds is silently replaced by the agent's 30s default, "+
			"so %ds gives slow nodes less time than asking for nothing: keep it at or under the bound",
			agentMaxAcceptedSec, got)
	}
	// Generous enough to matter: a 12 MiB binary at a slow-but-real 227 KiB/s
	// needs about a minute, and the leg before it is a TLS handshake over a
	// lossy link.
	if got < 300 {
		t.Fatalf("agent update timeout %ds is too tight for a slow uplink to fetch the binary", got)
	}
}

// seedAgentUpdateApproved plans an update for node-a (running 0.1.0, target
// 0.2.0), approves it, and returns the approval. Callers add the task and the
// node state the case needs.
func seedAgentUpdateApproved(t *testing.T, srv *Server, st *store.Store) model.Approval {
	t.Helper()
	seedAgentUpdateNode(t, st)
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	return approval
}

// The 2026-09-05 rollout: the apply task finished and the approval was
// awaiting confirmation; the new agent's hello set the node's version to the
// target, and the console's next listing judged the approval stale ("policy
// changed: current_version") and rejected it before the heartbeat could
// confirm it. The listing must read that version as the confirmation it is.
func TestAgentUpdateApprovalsListConfirmsAwaitingApprovalFromNodeVersion(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	approval := seedAgentUpdateApproved(t, srv, st)
	approval.Reason = agentUpdateAwaitingConfirmationReason("0.2.0")
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-done", ApprovalID: approval.ID, Targets: []string{"node-a"}, Status: model.TaskFinished, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.0", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list approvals failed: %d", list.StatusCode)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApplied {
		t.Fatalf("node at target version should confirm the update, not reject it: ok=%v approval=%+v", ok, stored)
	}
	if !strings.Contains(stored.Reason, "confirmed by the node's report") || !strings.Contains(stored.Reason, "0.2.0") {
		t.Fatalf("confirmed reason should name the node's report and version, got %q", stored.Reason)
	}
	policy, ok := st.AgentUpdatePolicy("node-a")
	if !ok || policy.LastAppliedVersion != "0.2.0" || policy.LastAppliedAt.IsZero() || policy.LastError != "" {
		t.Fatalf("listing confirmation should settle the policy too: ok=%v policy=%+v", ok, policy)
	}
}

// The result the old agent posts can be lost to the restart. The node's next
// report proves the update anyway: the plan froze current_version 0.1.0 and the
// node now runs 0.2.0.
func TestAgentUpdateReportConfirmsApprovedUpdateWithoutTaskResult(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	// The enrolled node keeps its token; the version the plan freezes comes
	// from a real hello rather than a node rewrite.
	if hello := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"0.1.0"}`, nodeToken); hello.Code != http.StatusOK {
		t.Fatalf("hello failed: %d %s", hello.Code, hello.Body.String())
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-lost", ApprovalID: approval.ID, Targets: []string{"node-a"}, Status: model.TaskLeased, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	// Not yet: the node still runs what the plan saw.
	hello := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"0.1.0"}`, nodeToken)
	if hello.Code != http.StatusOK {
		t.Fatalf("hello failed: %d %s", hello.Code, hello.Body.String())
	}
	if stored, ok := st.Approval(approval.ID); !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("old version must not confirm anything: ok=%v approval=%+v", ok, stored)
	}
	// Not yet: some other version is not the target either.
	hello = doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"0.1.5"}`, nodeToken)
	if hello.Code != http.StatusOK {
		t.Fatalf("hello failed: %d %s", hello.Code, hello.Body.String())
	}
	if stored, ok := st.Approval(approval.ID); !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("a version that is not the target must not confirm: ok=%v approval=%+v", ok, stored)
	}

	hello = doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"0.2.0"}`, nodeToken)
	if hello.Code != http.StatusOK {
		t.Fatalf("hello failed: %d %s", hello.Code, hello.Body.String())
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApplied || !strings.Contains(stored.Reason, "confirmed by the node's report: agent version 0.2.0") {
		t.Fatalf("target version should confirm the approval without a task result: ok=%v approval=%+v", ok, stored)
	}
	policy, ok := st.AgentUpdatePolicy("node-a")
	if !ok || policy.LastAppliedVersion != "0.2.0" || policy.LastError != "" {
		t.Fatalf("policy should record the confirmed version: ok=%v policy=%+v", ok, policy)
	}

	// The lost result arrives late (a re-run, or a slow post). It must not pull
	// the approval back to "awaiting confirmation".
	result := `{"node_id":"node-a","result":{"task_id":"task-lost","lease_id":"","exit_code":0,"stdout":"installed"}}`
	resultRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", result, nodeToken)
	if resultRec.Code != http.StatusOK && resultRec.Code != http.StatusForbidden && resultRec.Code != http.StatusConflict {
		t.Fatalf("late task result: %d %s", resultRec.Code, resultRec.Body.String())
	}
	if again, ok := st.Approval(approval.ID); !ok || again.Status != model.ApprovalApplied {
		t.Fatalf("a late result must not regress an applied approval: ok=%v approval=%+v", ok, again)
	}
}

// A forced reinstall plans the version the node already runs, so the node
// reporting that version proves nothing; only its task result can.
func TestAgentUpdateReportDoesNotConfirmSameVersionReinstall(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.0", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", true, "manual", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := srv.reconcileAgentUpdateHeartbeat(httptest.NewRequest(http.MethodPost, "/api/agent/hello", nil), "node-a", "0.2.0", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("same-version reinstall must wait for its task result: ok=%v approval=%+v", ok, stored)
	}
	approval.Reason = agentUpdateAwaitingConfirmationReason("0.2.0")
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := srv.reconcileAgentUpdateHeartbeat(httptest.NewRequest(http.MethodPost, "/api/agent/hello", nil), "node-a", "0.2.0", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if stored, ok := st.Approval(approval.ID); !ok || stored.Status != model.ApprovalApplied {
		t.Fatalf("once the task result is in, the report confirms the reinstall: ok=%v approval=%+v", ok, stored)
	}
}

// The staleness sweep decides on a snapshot; the write must re-check the live
// row so it cannot overwrite a transition committed in between.
func TestRejectStaleAgentUpdateApprovalSkipsRowAppliedMeanwhile(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	approval := seedAgentUpdateApproved(t, srv, st)
	snapshot := approval
	applied := approval
	applied.Status = model.ApprovalApplied
	applied.Reason = agentUpdateConfirmedReason(approval.Plan, "0.2.0")
	if err := st.UpsertApproval(applied); err != nil {
		t.Fatal(err)
	}
	if err := srv.rejectAgentUpdateApprovalWithReason(snapshot, "policy changed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApplied || stored.Reason != applied.Reason {
		t.Fatalf("a stale snapshot must not reject an applied approval: ok=%v approval=%+v", ok, stored)
	}
}

// The restart is what makes the result post racy, so the script has to post
// first: it must hand the restart to a transient systemd unit that fires after
// the script has exited, install before scheduling it, and do nothing after.
func TestAgentUpdateApplyScriptDetachesTheRestartAfterInstall(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	approval := seedAgentUpdateApproved(t, srv, st)
	script, err := agentUpdateApplyScript(approval, srv.publicURL)
	if err != nil {
		t.Fatal(err)
	}
	install := strings.Index(script, "mv \"$TARGET.new\" \"$TARGET\"")
	schedule := strings.Index(script, "systemd-run --unit=\"$RESTART_UNIT\" --on-active=3s /bin/systemctl restart \"$SERVICE\"")
	if install < 0 || schedule < 0 || schedule < install {
		t.Fatalf("the restart must be scheduled through systemd-run after the binary is in place:\n%s", script)
	}
	if strings.Contains(script, "\nsystemctl restart") || strings.Contains(script, "\nsystemctl stop") {
		t.Fatalf("the script must never restart the service in its own cgroup; it would kill the agent before the result is posted:\n%s", script)
	}
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "echo ") || !strings.Contains(last, "scheduled $SERVICE restart") {
		t.Fatalf("after scheduling the restart the script may only report and exit, got %q", last)
	}
}

// An approval the operator approved without queuing its apply has no task, so
// nothing it authorized has run. If the node then reaches the target version
// by some other route (another approval, a manual upgrade), that version is
// not this approval's doing: the report must not mark it applied, and neither
// heartbeat nor listing may write an agent.update.applied audit event for it.
// A task that was queued but never leased proves as little. Only a task the
// node actually took makes the version change this approval's evidence.
func TestAgentUpdateReportDoesNotConfirmApprovalWhoseTaskNeverRan(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	approval := seedAgentUpdateApproved(t, srv, st)
	req := httptest.NewRequest(http.MethodPost, "/api/agent/hello", nil)
	appliedAudits := func() int {
		n := 0
		for _, ev := range st.AuditEvents() {
			if ev.Action == "agent.update.applied" && ev.Metadata["approval_id"] == approval.ID {
				n++
			}
		}
		return n
	}

	// No task at all: the "approve without queuing" shape.
	if err := srv.reconcileAgentUpdateHeartbeat(req, "node-a", "0.2.0", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if stored, ok := st.Approval(approval.ID); !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("a version match with no apply task must not confirm the approval: ok=%v approval=%+v", ok, stored)
	}
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentVersion: "0.2.0", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := srv.rejectLocallyStaleAgentUpdateApprovals(httptest.NewRequest(http.MethodGet, "/api/network/approvals", nil), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if stored, ok := st.Approval(approval.ID); !ok || stored.Status == model.ApprovalApplied {
		t.Fatalf("the listing sweep must not confirm an approval whose task never ran: ok=%v approval=%+v", ok, stored)
	}
	if n := appliedAudits(); n != 0 {
		t.Fatalf("no agent.update.applied audit event may name an approval nothing executed, got %d", n)
	}
	if policy, ok := st.AgentUpdatePolicy("node-a"); !ok || policy.LastAppliedVersion != "" {
		t.Fatalf("policy must not record an applied version for an approval that never ran: ok=%v policy=%+v", ok, policy)
	}

	// Queued but never leased: the node never received the script.
	approval.Status = model.ApprovalApproved
	approval.Reason = ""
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTask(model.Task{ID: "task-queued", ApprovalID: approval.ID, Targets: []string{"node-a"}, Status: model.TaskQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := srv.reconcileAgentUpdateHeartbeat(req, "node-a", "0.2.0", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if stored, ok := st.Approval(approval.ID); !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("a queued task the node never took must not confirm the approval: ok=%v approval=%+v", ok, stored)
	}
	if n := appliedAudits(); n != 0 {
		t.Fatalf("no agent.update.applied audit event for a task that never ran, got %d", n)
	}

	// Leased by the node: the task ran and its result was lost to the restart.
	task, ok := st.Task("task-queued")
	if !ok {
		t.Fatal("task-queued missing")
	}
	task.Status = model.TaskLeased
	task.LeasedBy = "node-a"
	task.LeaseID = "lease-1"
	task.StartedAt = time.Now().UTC()
	task.TargetLeases = map[string]model.TaskLease{"node-a": {LeaseID: "lease-1", StartedAt: task.StartedAt}}
	// CreateTask writes the row by id, so this replaces the queued one.
	if err := st.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if err := srv.reconcileAgentUpdateHeartbeat(req, "node-a", "0.2.0", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApplied || !strings.Contains(stored.Reason, "confirmed by the node's report: agent version 0.2.0") {
		t.Fatalf("once the node took the task, its report confirms the approval: ok=%v approval=%+v", ok, stored)
	}
	if n := appliedAudits(); n != 1 {
		t.Fatalf("exactly one agent.update.applied audit event for the confirmed approval, got %d", n)
	}
}
