package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// adoptNodeWithWebGroup gives n1 a legacy baseline that NetGuard does not use
// (public tcp/22 and tcp/8080) and a managed binding whose security group
// allows tcp/22 and tcp/443 from the public zone and drops 192.0.2.0/24. The
// deny turns the compiler's fast path off, so the group's rules render with
// their comments and a plan built from the legacy baseline cannot pass for
// one built from the binding.
func adoptNodeWithWebGroup(t *testing.T, handler http.Handler, st *store.Store, cookies []*http.Cookie, csrf string) {
	t.Helper()
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"n1","interface_name":"ens3","wireguard_cidr":"10.66.0.0/24","public_tcp":[22,8080]
	}`, cookies, csrf)
	save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}
	public := model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic}
	group, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-web", Name: "web", Rules: []model.GuardRule{
		{ID: "drop-doc", Comment: "drop documentation net", Action: model.NetRuleDeny, Direction: model.NetDirIngress, Protocol: model.NetProtoAny, Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "192.0.2.0/24"}},
		{ID: "ssh", Comment: "web ssh", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 22, To: 22}}, Remote: public},
		{ID: "https", Comment: "web https", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 443, To: 443}}, Remote: public},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", GroupIDs: []string{group.ID}, Managed: true}); err != nil {
		t.Fatal(err)
	}
	seedNodeReality(t, st, "n1", 22, "ens3")
}

// On a node NetGuard manages, the DNS plan used to rebuild lattice_guard from
// the legacy NFTInputs baseline, so approving it silently dropped every
// security group bound to the node. It now renders through the NetGuard
// compile with the DNS listener ports added, the way the beacon companion
// does (design 32 D7).
func TestDNSPlanOnManagedNodeRendersNetGuardBindingPlusDNSPorts(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	depID := createDNSDeployment(t, handler, cookies, csrf)

	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(planRes.Body)
		t.Fatalf("dns plan on a managed node failed: %d %s", planRes.StatusCode, body)
	}
	plan := decodeDNSPlan(t, planRes).Plan
	for _, want := range []string{
		`comment "drop documentation net"`,
		`comment "web ssh"`,
		`comment "web https"`,
		`ip saddr @wg_peers4 udp dport { 53 }`,
		`ip saddr @wg_peers4 tcp dport { 53 }`,
		"firewall: NetGuard binding",
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("dns plan on a managed node missing %q:\n%s", want, plan)
		}
	}
	for _, unwanted := range []string{"nft inputs source", "8080"} {
		if strings.Contains(plan, unwanted) {
			t.Fatalf("dns plan on a managed node must not use the legacy baseline (%q):\n%s", unwanted, plan)
		}
	}
	if !auditMetadataSeen(st, "dns.plan", "nft_source", "netguard") {
		t.Fatalf("dns.plan audit must name netguard as the firewall source: %+v", st.AuditEvents())
	}
}

// A DNS plan on an adopted node carries a NetGuard compile, so approving it
// after the binding's groups changed would roll the firewall back to what the
// plan saw. The approve recomputes and refuses a stale plan.
func TestDNSApproveOnManagedNodeRefusesStaleNetGuardIntent(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	depID := createDNSDeployment(t, handler, cookies, csrf)

	plan := func() model.Approval {
		t.Helper()
		res := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("dns plan failed: %d", res.StatusCode)
		}
		return decodeDNSPlan(t, res)
	}
	approve := func(a model.Approval) int {
		t.Helper()
		res := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
			string(mustJSON(t, map[string]any{"approval_id": a.ID, "queue_apply": true, "plan_sha256": planSHA256(a.Plan)})), cookies, csrf)
		res.Body.Close()
		return res.StatusCode
	}

	stale := plan()
	group, ok := st.SecurityGroup("sg-web")
	if !ok {
		t.Fatal("missing group")
	}
	group.Rules = append(group.Rules, model.GuardRule{
		ID: "drop-more", Comment: "drop another net", Action: model.NetRuleDeny, Direction: model.NetDirIngress,
		Protocol: model.NetProtoAny, Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "198.51.100.0/24"},
	})
	if _, err := st.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	if code := approve(stale); code != http.StatusConflict {
		t.Fatalf("approving a DNS plan made before the group changed = %d, want 409", code)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("a refused approval must queue nothing: %+v", st.Tasks())
	}

	fresh := plan()
	if !strings.Contains(fresh.Plan, `comment "drop another net"`) {
		t.Fatalf("a fresh plan must carry the new rule:\n%s", fresh.Plan)
	}
	if code := approve(fresh); code != http.StatusOK {
		t.Fatalf("approving a current DNS plan = %d, want 200", code)
	}
}

// Every NetGuard compile of a node carries the DNS listeners its approved
// plans opened, so a NetGuard plan made after the resolver is approved keeps
// its ports. The set comes from the approved plan, not the stored record: a
// deployment never approved opens nothing, and editing a running deployment
// moves no port until its new plan is approved.
func TestNetGuardPlanKeepsDNSPortsOfApprovedPlans(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	depID := createDNSDeployment(t, handler, cookies, csrf)

	netguardPlan := func() string {
		t.Helper()
		res := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"n1"}`, cookies, csrf)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(res.Body)
			t.Fatalf("netguard plan failed: %d %s", res.StatusCode, body)
		}
		var out struct {
			Approval model.Approval `json:"approval"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.Approval.Plan
	}

	if plan := netguardPlan(); strings.Contains(plan, "dport { 53 }") {
		t.Fatalf("a deployment never approved must not open its port:\n%s", plan)
	}

	// Approved but never queued: nothing runs, so nothing opens.
	unqueuedRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
	unqueued := decodeDNSPlan(t, unqueuedRes)
	unqueuedRes.Body.Close()
	approveOnly := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": unqueued.ID, "queue_apply": false, "plan_sha256": planSHA256(unqueued.Plan)})), cookies, csrf)
	approveOnly.Body.Close()
	if approveOnly.StatusCode != http.StatusOK {
		t.Fatalf("approve without queue: %d", approveOnly.StatusCode)
	}
	if plan := netguardPlan(); strings.Contains(plan, "dport { 53 }") {
		t.Fatalf("an approval never queued must not open its port:\n%s", plan)
	}

	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
	dnsApproval := decodeDNSPlan(t, planRes)
	planRes.Body.Close()
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": dnsApproval.ID, "queue_apply": true, "plan_sha256": planSHA256(dnsApproval.Plan)})), cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve dns plan: %d", approve.StatusCode)
	}
	plan := netguardPlan()
	for _, want := range []string{`ip saddr @wg_peers4 udp dport { 53 }`, `ip saddr @wg_peers4 tcp dport { 53 }`, `comment "web https"`} {
		if !strings.Contains(plan, want) {
			t.Fatalf("netguard plan must keep the approved resolver's ports (%q):\n%s", want, plan)
		}
	}

	// An edit to the stored deployment, with no plan approved for it, opens
	// and closes nothing.
	edit := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"id":"`+depID+`","name":"private dns","node_id":"n1","listen_port":5353,
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	edit.Body.Close()
	if edit.StatusCode != http.StatusOK {
		t.Fatalf("edit deployment: %d", edit.StatusCode)
	}
	plan = netguardPlan()
	if strings.Contains(plan, "5353") || !strings.Contains(plan, `ip saddr @wg_peers4 udp dport { 53 }`) {
		t.Fatalf("an unapproved edit must not move the resolver's ports:\n%s", plan)
	}

	// A failed re-apply leaves the resolver on the plan that last applied,
	// so its ports stay; an apply that never succeeded opens nothing.
	failed, _ := st.Approval(dnsApproval.ID)
	failed.Status = model.ApprovalRejected
	if err := st.UpsertApproval(failed); err != nil {
		t.Fatal(err)
	}
	if plan := netguardPlan(); strings.Contains(plan, "dport { 53 }") {
		t.Fatalf("a plan that never applied must not hold ports open:\n%s", plan)
	}
	failed.Status = model.ApprovalApplied
	if err := st.UpsertApproval(failed); err != nil {
		t.Fatal(err)
	}
	if plan := netguardPlan(); !strings.Contains(plan, `ip saddr @wg_peers4 udp dport { 53 }`) {
		t.Fatalf("an applied plan must keep its ports:\n%s", plan)
	}

	// Disabling the deployment asks for the resolver to stop serving, so its
	// ports may close before a DNS plan for the disabled state applies.
	disable := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"id":"`+depID+`","name":"private dns","node_id":"n1","disabled":true,
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	disable.Body.Close()
	if disable.StatusCode != http.StatusOK {
		t.Fatalf("disable deployment: %d", disable.StatusCode)
	}
	if plan := netguardPlan(); strings.Contains(plan, "dport { 53 }") {
		t.Fatalf("a disabled deployment must not hold its ports open:\n%s", plan)
	}
}

// A DNS plan composed through NetGuard applies the node's whole NetGuard
// intent, so planning and deciding it take netguard:admin, as a NetGuard plan
// does; and a node un-adopted between plan and approve refuses the plan.
func TestDNSPlanOnManagedNodeNeedsNetGuardAdminAndAdoption(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	depID := createDNSDeployment(t, handler, cookies, csrf)
	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
	approval := decodeDNSPlan(t, planRes)
	planRes.Body.Close()
	if !strings.Contains(approval.Plan, "source: netguard") || !strings.Contains(approval.Plan, "listen: mesh udp 53") {
		t.Fatalf("plan must record its firewall source and listeners:\n%s", approval.Plan)
	}

	dnsOnly := principal{Principal: rbac.Principal{ActorID: "dns-operator", Scopes: []string{"dns:admin", "network:plan", "network:apply", "netguard:read"}}}
	_, err := srv.approveApprovalCore(context.Background(), dnsOnly, approval, true, planSHA256(approval.Plan))
	var decision *approvalDecisionError
	if !errors.As(err, &decision) || decision.status != http.StatusForbidden {
		t.Fatalf("deciding a NetGuard-composed DNS plan without netguard:admin = %v, want 403", err)
	}

	binding, _ := st.NodeGuardBinding("n1")
	binding.Managed = false
	if _, err := st.UpsertNodeGuardBinding(binding); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("approving a NetGuard-composed plan after the node was un-adopted = %d, want 409", res.StatusCode)
	}
}

// The legacy Network Guard route composes lattice_guard from NFTInputs and
// knows nothing of security groups, so on a node NetGuard manages it would
// replace the node's firewall with the legacy baseline. It refuses instead,
// and keeps working for a node with only the observe-only record.
func TestLegacyNFTPlanRefusesManagedNode(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"n1"}`, cookies, csrf)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict || !strings.Contains(string(body), "NetGuard") {
		t.Fatalf("legacy nft plan on a managed node = %d %s, want 409 naming NetGuard", res.StatusCode, body)
	}
	if len(st.Approvals()) != 0 {
		t.Fatalf("a refused legacy plan must not record an approval: %+v", st.Approvals())
	}

	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n2"}); err != nil {
		t.Fatal(err)
	}
	seedNodeReality(t, st, "n2", 22, "eth0")
	observe := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"n2","public_tcp":[22]}`, cookies, csrf)
	observe.Body.Close()
	if observe.StatusCode != http.StatusOK {
		t.Fatalf("legacy nft plan on an observe-only node = %d, want 200", observe.StatusCode)
	}
}
