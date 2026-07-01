package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestApprovalDecisionExtraScope(t *testing.T) {
	cases := []struct {
		plugin string
		want   string
	}{
		{plugin: agentUpdatePlugin, want: "node:admin"},
		{plugin: "selfdns", want: "dns:admin"},
		{plugin: proxyCorePlugin, want: "proxy:admin"},
		{plugin: "cftunnel", want: "tunnel:admin"},
		{plugin: "nftpolicy", want: "netpolicy:admin"},
		{plugin: "wireguard", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.plugin, func(t *testing.T) {
			got := approvalDecisionExtraScope(model.Approval{Plugin: tc.plugin})
			if got != tc.want {
				t.Fatalf("extra scope = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAgentUpdateApprovalDecisionRequiresNodeAdmin(t *testing.T) {
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
	approval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "manual", time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	networkOnly := createPAT(t, handler, cookies, csrf, []string{"network:apply"}, []string{"node-a"})
	approve := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan)})),
		networkOnly)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusForbidden {
		t.Fatalf("network-only token should not approve agent update, got %d", approve.StatusCode)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalPending {
		t.Fatalf("denied approve should leave approval pending: ok=%v approval=%+v", ok, stored)
	}

	reject := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/reject",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID})),
		networkOnly)
	defer reject.Body.Close()
	if reject.StatusCode != http.StatusForbidden {
		t.Fatalf("network-only token should not reject agent update, got %d", reject.StatusCode)
	}
	stored, ok = st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalPending {
		t.Fatalf("denied reject should leave approval pending: ok=%v approval=%+v", ok, stored)
	}

	withNodeAdmin := createPAT(t, handler, cookies, csrf, []string{"network:apply", "node:admin"}, []string{"node-a"})
	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan)})),
		withNodeAdmin)
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		var apiErr model.APIErrorResponse
		_ = json.NewDecoder(allowed.Body).Decode(&apiErr)
		t.Fatalf("node admin token should approve agent update, got %d %+v", allowed.StatusCode, apiErr)
	}
	stored, ok = st.Approval(approval.ID)
	if !ok || stored.Status != model.ApprovalApproved {
		t.Fatalf("allowed approve should record approval: ok=%v approval=%+v", ok, stored)
	}
}

func TestApprovalListRequiresDomainVisibilityScope(t *testing.T) {
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
	approval, err := srv.createAgentUpdateApproval("node-a", "admin", false, "manual", time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	networkPlanOnly := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", networkPlanOnly)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusOK {
		t.Fatalf("approval list should return a filtered list, got %d", denied.StatusCode)
	}
	if got := decodeApprovalViews(t, denied); len(got) != 0 {
		t.Fatalf("network planner should not see agent update approval without node:admin: %+v", got)
	}

	withNodeAdmin := createPAT(t, handler, cookies, csrf, []string{"network:plan", "node:admin"}, []string{"node-a"})
	allowed := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", withNodeAdmin)
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("approval list failed: %d", allowed.StatusCode)
	}
	got := decodeApprovalViews(t, allowed)
	if len(got) != 1 || got[0].ID != approval.ID {
		t.Fatalf("node admin should see agent update approval, got %+v", got)
	}
}

func TestApprovalListAllowsDomainOwnedApprovalWithoutNetworkPlan(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	approval := model.Approval{
		ID:        "approval-netpolicy",
		NodeID:    "node-a",
		Plugin:    "nftpolicy",
		Action:    nftPolicyApplyAction,
		Plan:      "table inet lattice_policy {}\n",
		Status:    model.ApprovalPending,
		CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	}
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}

	netpolicyAdmin := createPAT(t, handler, cookies, csrf, []string{"netpolicy:admin"}, []string{"node-a"})
	res := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", netpolicyAdmin)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("domain admin should list own approval domain, got %d", res.StatusCode)
	}
	got := decodeApprovalViews(t, res)
	if len(got) != 1 || got[0].ID != approval.ID {
		t.Fatalf("netpolicy admin should see netpolicy approval, got %+v", got)
	}
}

func decodeApprovalViews(t *testing.T, res *http.Response) []approvalView {
	t.Helper()
	var views []approvalView
	if err := json.NewDecoder(res.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	return views
}
