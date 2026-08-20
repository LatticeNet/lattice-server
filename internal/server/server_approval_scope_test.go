package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestApprovalDecisionExtraScope(t *testing.T) {
	cases := []struct {
		name   string
		plugin string
		action string
		want   string
	}{
		// Plugin "nft" carries two approvals with different authoring gates, so
		// the mapping is keyed on the action for this plugin. Authoring a
		// netguard ruleset requires netguard:admin; deciding one must too, or
		// bare network:apply dispatches a firewall change it could not write.
		{name: "netguard", plugin: "nft", action: netGuardApprovalAction, want: "netguard:admin"},
		// The legacy nft path only requires network:plan to author, so it stays
		// uncovered on purpose rather than gaining a gate it never had.
		{name: "legacy nft", plugin: "nft", action: "apply-ruleset", want: ""},
		{plugin: agentUpdatePlugin, want: "node:admin"},
		{plugin: "selfdns", want: "dns:admin"},
		{plugin: proxyCorePlugin, want: "proxy:admin"},
		{plugin: singBoxLineUserPlugin, want: "vpncore:admin"},
		{plugin: singBoxLineMetaPlugin, want: "vpncore:admin"},
		{plugin: "cftunnel", want: "tunnel:admin"},
		{plugin: "nftpolicy", want: "netpolicy:admin"},
		{plugin: "wireguard", want: ""},
	}
	for _, tc := range cases {
		name := tc.name
		if name == "" {
			name = tc.plugin
		}
		t.Run(name, func(t *testing.T) {
			got := approvalDecisionExtraScope(model.Approval{Plugin: tc.plugin, Action: tc.action})
			if got != tc.want {
				t.Fatalf("extra scope = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDesign15ApprovalsRequireVPNCoreAdmin(t *testing.T) {
	for _, pluginID := range []string{singBoxLineUserPlugin, singBoxLineMetaPlugin} {
		t.Run(pluginID, func(t *testing.T) {
			srv, handler, st := newInventoryServer(t)
			seedLinemetaNodes(t, srv)
			var approval model.Approval
			if pluginID == singBoxLineUserPlugin {
				line, user := seedLineUserFixture(t, srv)
				user.Bindings = nil
				if err := srv.putVpnUser(user); err != nil {
					t.Fatal(err)
				}
				out, err := srv.vpnUserLinePlan(lineUserTestPrincipal(), mustJSON(t, map[string]string{
					"user_id": user.ID, "line_hash_id": line.LineHashID,
				}), lineUserOpAdd)
				if err != nil {
					t.Fatal(err)
				}
				var response struct {
					Approval model.Approval `json:"approval"`
				}
				_ = json.Unmarshal(out, &response)
				approval = response.Approval
			} else {
				out, err := srv.queueLineMetaSync(lineUserTestPrincipal(), "node-a")
				if err != nil {
					t.Fatal(err)
				}
				var response struct {
					Approval model.Approval `json:"approval"`
				}
				_ = json.Unmarshal(out, &response)
				approval = response.Approval
			}
			cookies, csrf := loginSession(t, handler)
			networkOnly := createPAT(t, handler, cookies, csrf, []string{"network:apply"}, []string{"node-a"})
			denied := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
				string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan)})), networkOnly)
			defer denied.Body.Close()
			if denied.StatusCode != http.StatusForbidden {
				t.Fatalf("network-only approval must fail closed, got %d", denied.StatusCode)
			}
			if got, _ := st.Approval(approval.ID); got.Status != model.ApprovalPending {
				t.Fatalf("denied decision mutated approval: %+v", got)
			}

			// Legacy proxy:admin remains a compatibility grant for canonical
			// vpncore:admin while operators migrate their PATs.
			legacy := createPAT(t, handler, cookies, csrf, []string{"network:apply", "proxy:admin"}, []string{"node-a"})
			allowed := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
				string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": false, "plan_sha256": planSHA256(approval.Plan)})), legacy)
			defer allowed.Body.Close()
			if allowed.StatusCode != http.StatusOK {
				t.Fatalf("legacy proxy:admin compatibility approval failed: %d", allowed.StatusCode)
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC))
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
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC))
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

// TestNetGuardApprovalDecisionRequiresNetGuardAdmin is the end-to-end half of
// the mapping table above. The unit case proves approvalDecisionExtraScope
// returns the right string; this proves the string is actually enforced at the
// approve endpoint, which is where the gap lived: authoring a netguard ruleset
// requires netguard:admin (handleNetGuardPlan), but deciding one used to need
// only network:apply, so a bare network:apply holder could dispatch a firewall
// change they were never allowed to write.
//
// The assertions are deliberately about the SCOPE GATE and nothing further. A
// principal that clears the gate still meets the plan-hash and
// current-plan-binding checks, which depend on stored guard state this test
// does not seed, so "cleared the gate" is asserted as "not 403" rather than a
// specific success code. Asserting 200 would couple this test to machinery it
// is not exercising.
func TestNetGuardApprovalDecisionRequiresNetGuardAdmin(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	_ = srv
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)

	const plan = "table inet lattice_guard {\n}\n"
	seed := func(t *testing.T, id, action string) model.Approval {
		t.Helper()
		a := model.Approval{
			ID: id, NodeID: "node-a", Plugin: "nft", Action: action,
			Plan: plan, Status: model.ApprovalPending, ActorID: "admin",
			CreatedAt: time.Now().UTC(),
		}
		if err := st.UpsertApproval(a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	approve := func(t *testing.T, a model.Approval, token string) int {
		t.Helper()
		resp := doBearerJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
			string(mustJSON(t, map[string]any{
				"approval_id": a.ID, "queue_apply": false, "plan_sha256": planSHA256(a.Plan),
			})), token)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	networkOnly := createPAT(t, handler, cookies, csrf, []string{"network:apply"}, []string{"node-a"})
	guardAdmin := createPAT(t, handler, cookies, csrf, []string{"network:apply", "netguard:admin"}, []string{"node-a"})

	t.Run("network-only is refused", func(t *testing.T) {
		a := seed(t, "approval_ng_denied", netGuardApprovalAction)
		if got := approve(t, a, networkOnly); got != http.StatusForbidden {
			t.Fatalf("network-only must fail closed on a netguard approval, got %d", got)
		}
		if stored, ok := st.Approval(a.ID); !ok || stored.Status != model.ApprovalPending {
			t.Fatalf("refused decision must not mutate the approval: ok=%v approval=%+v", ok, stored)
		}
	})

	t.Run("netguard admin clears the gate", func(t *testing.T) {
		a := seed(t, "approval_ng_allowed", netGuardApprovalAction)
		if got := approve(t, a, guardAdmin); got == http.StatusForbidden {
			t.Fatal("netguard:admin must clear the decision scope gate, got 403")
		}
	})

	// The legacy nft path only requires network:plan to author, so demanding
	// netguard:admin to decide would add a gate it never had. This pins the
	// exclusion: widening the mapping to the whole "nft" plugin breaks here.
	t.Run("legacy apply-ruleset is not tightened", func(t *testing.T) {
		a := seed(t, "approval_ng_legacy", "apply-ruleset")
		if got := approve(t, a, networkOnly); got == http.StatusForbidden {
			t.Fatal("legacy apply-ruleset must not gain a netguard:admin gate, got 403")
		}
	})
}
