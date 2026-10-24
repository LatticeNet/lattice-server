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
