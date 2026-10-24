package server

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// adoptNodeWithWebGroup gives n1 a legacy baseline that NetGuard does not use
// (public tcp/22 and tcp/8080) and a managed binding whose security group
// allows tcp/22 and tcp/443 from the public zone and drops 192.0.2.0/24.
// extra rules are appended to the group.
func adoptNodeWithWebGroup(t *testing.T, handler http.Handler, st *store.Store, cookies []*http.Cookie, csrf string, extra ...model.GuardRule) {
	t.Helper()
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"n1","interface_name":"ens3","wireguard_cidr":"10.66.0.0/24","public_tcp":[22,8080]
	}`, cookies, csrf)
	save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}
	public := model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic}
	rules := []model.GuardRule{
		{ID: "drop-doc", Comment: "drop documentation net", Action: model.NetRuleDeny, Direction: model.NetDirIngress, Protocol: model.NetProtoAny, Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "192.0.2.0/24"}},
		{ID: "ssh", Comment: "web ssh", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 22, To: 22}}, Remote: public},
		{ID: "https", Comment: "web https", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 443, To: 443}}, Remote: public},
	}
	group, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-web", Name: "web", Rules: append(rules, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", GroupIDs: []string{group.ID}, Managed: true}); err != nil {
		t.Fatal(err)
	}
	seedNodeReality(t, st, "n1", 22, "ens3")
}

// The legacy Network Guard route composes lattice_guard from NFTInputs and
// knows nothing of security groups, so on a node NetGuard manages it would
// replace the node's firewall with the legacy baseline. It refuses instead,
// and keeps working for a node with only the observe-only record.
// TestLegacyNFTPlanMadeBeforeAdoptionCannotApply covers the approve.
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

// On a node NetGuard manages, the DNS plan used to rebuild lattice_guard from
// the legacy baseline and drop every bound security group. NetGuard is now
// the one writer there: the DNS plan installs CoreDNS only, and refuses until
// NetGuard already admits the deployment's listeners (design 32 D7).
func TestDNSPlanOnManagedNodeInstallsCoreDNSOnly(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	depID := createDNSDeployment(t, handler, cookies, csrf)

	closed := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
	body, _ := io.ReadAll(closed.Body)
	closed.Body.Close()
	if closed.StatusCode != http.StatusConflict || !strings.Contains(string(body), "open udp/53 and tcp/53 from the WireGuard range in a security group on tokyo-1 first") {
		t.Fatalf("dns plan with closed ports on a managed node = %d %s, want 409 saying what to open", closed.StatusCode, body)
	}
	if len(st.Approvals()) != 0 {
		t.Fatalf("a refused dns plan must not record an approval: %+v", st.Approvals())
	}

	group, _ := st.SecurityGroup("sg-web")
	wireguard := model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZoneWireGuard}
	for _, proto := range []string{model.NetProtoUDP, model.NetProtoTCP} {
		group.Rules = append(group.Rules, model.GuardRule{ID: "dns-" + proto, Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: proto, Ports: []model.GuardPortRange{{From: 53, To: 53}}, Remote: wireguard})
	}
	if _, err := st.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	open := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
	defer open.Body.Close()
	if open.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(open.Body)
		t.Fatalf("dns plan with open ports on a managed node = %d %s", open.StatusCode, b)
	}
	approval := decodeDNSPlan(t, open)
	for _, want := range []string{"NetGuard manages this table on the node. This plan does not change it.", "NetGuard admits udp/53", "NetGuard admits tcp/53", "forward . 1.1.1.1"} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, approval.Plan)
		}
	}
	for _, unwanted := range []string{"## nftables lattice_guard candidate", "table inet lattice_guard", "nft inputs source"} {
		if strings.Contains(approval.Plan, unwanted) {
			t.Fatalf("a plan under NetGuard must not carry a ruleset (%q):\n%s", unwanted, approval.Plan)
		}
	}
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve dns plan under NetGuard: %d", approve.StatusCode)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("approve should queue one task: %+v", tasks)
	}
	script := tasks[0].Script
	if strings.Contains(script, "nft") || strings.Contains(script, "lattice_guard") || strings.Contains(script, "guard.nft") {
		t.Fatalf("the apply script under NetGuard must never touch lattice_guard:\n%s", script)
	}
	for _, want := range []string{"lattice-selfdns.service", "start_watchdog", "rolling back config"} {
		if !strings.Contains(script, want) {
			t.Fatalf("apply script missing %q:\n%s", want, script)
		}
	}
}

// A DNS plan composed on the legacy path carries a lattice_guard ruleset. If
// NetGuard adopts the node before it is approved, applying it would replace
// the adopted firewall, so the approve refuses it, naming NetGuard. The same
// path serves auto-approval.
func TestDNSApproveRefusesFirewallPlanOnManagedNode(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"n1","interface_name":"ens3","wireguard_cidr":"10.66.0.0/24","public_tcp":[22]
	}`, cookies, csrf)
	save.Body.Close()
	seedNodeReality(t, st, "n1", 22, "ens3")
	depID := createDNSDeployment(t, handler, cookies, csrf)
	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+depID+`"}`, cookies, csrf)
	approval := decodeDNSPlan(t, planRes)
	planRes.Body.Close()
	if !strings.Contains(approval.Plan, "## nftables lattice_guard candidate") {
		t.Fatalf("a legacy-path dns plan carries a ruleset:\n%s", approval.Plan)
	}

	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "n1", Managed: true}); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict || !strings.Contains(string(body), "NetGuard") {
		t.Fatalf("approving a firewall-writing dns plan on a managed node = %d %s, want 409 naming NetGuard", res.StatusCode, body)
	}
	if len(st.Tasks()) != 0 {
		t.Fatalf("a refused approval must queue nothing: %+v", st.Tasks())
	}
}
