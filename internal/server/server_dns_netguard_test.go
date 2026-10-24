package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
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

// Every NetGuard compile of a node carries the DNS listeners its deployments
// put in force, so a NetGuard plan made after the resolver is running keeps
// its ports open. A deployment that was never approved contributes nothing.
func TestNetGuardPlanKeepsDNSPortsOfDeploymentsInForce(t *testing.T) {
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
		t.Fatalf("a pending deployment must not open its port:\n%s", plan)
	}
	dep, ok := st.DNSDeployment(depID)
	if !ok {
		t.Fatal("missing deployment")
	}
	dep.Status = model.DNSStatusRunning
	if err := st.UpsertDNSDeployment(dep); err != nil {
		t.Fatal(err)
	}
	plan := netguardPlan()
	for _, want := range []string{`ip saddr @wg_peers4 udp dport { 53 }`, `ip saddr @wg_peers4 tcp dport { 53 }`, `comment "web https"`} {
		if !strings.Contains(plan, want) {
			t.Fatalf("netguard plan must keep the running resolver's ports (%q):\n%s", want, plan)
		}
	}

	dep.Disabled = true
	dep.Status = model.DNSStatusDisabled
	if err := st.UpsertDNSDeployment(dep); err != nil {
		t.Fatal(err)
	}
	if plan := netguardPlan(); strings.Contains(plan, "dport { 53 }") {
		t.Fatalf("a disabled deployment must not keep its port open:\n%s", plan)
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
