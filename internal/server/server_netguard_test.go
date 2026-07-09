package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type netGuardGroupsResponse struct {
	Groups []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Source string `json:"source"`
		NodeID string `json:"node_id"`
		Rules  []struct {
			ID       string `json:"id"`
			Action   string `json:"action"`
			Protocol string `json:"protocol"`
			Ports    []struct {
				From int `json:"from"`
				To   int `json:"to"`
			} `json:"ports"`
			Remote struct {
				Kind   string `json:"kind"`
				ZoneID string `json:"zone_id"`
			} `json:"remote"`
		} `json:"rules"`
	} `json:"groups"`
}

type netGuardNodesResponse struct {
	Nodes []struct {
		NodeID   string `json:"node_id"`
		NodeName string `json:"node_name"`
		Source   string `json:"source"`
		Binding  struct {
			Managed  bool     `json:"managed"`
			GroupIDs []string `json:"group_ids"`
			ZoneIDs  []string `json:"zone_ids"`
		} `json:"binding"`
		Zones []struct {
			ID         string   `json:"id"`
			Builtin    bool     `json:"builtin"`
			Interfaces []string `json:"interfaces"`
			CIDRs      []string `json:"cidrs"`
		} `json:"zones"`
	} `json:"nodes"`
}

func TestNetGuardLegacyReadOnlyViews(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"node-a",
		"interface_name":"ens3",
		"wireguard_cidr":"10.66.0.0/24",
		"public_tcp":[22,9009,9010,9011,9012,9013],
		"public_udp":[51820]
	}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}

	nodesRes := doJSON(t, handler, http.MethodGet, "/api/netguard/nodes", "", cookies, csrf)
	defer nodesRes.Body.Close()
	if nodesRes.StatusCode != http.StatusOK {
		t.Fatalf("netguard nodes failed: %d", nodesRes.StatusCode)
	}
	var nodes netGuardNodesResponse
	if err := json.NewDecoder(nodesRes.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes.Nodes) != 1 {
		t.Fatalf("want 1 node view, got %d", len(nodes.Nodes))
	}
	node := nodes.Nodes[0]
	if node.NodeID != "node-a" || node.NodeName != "Node A" || node.Source != "legacy" {
		t.Fatalf("bad node view: %+v", node)
	}
	if node.Binding.Managed {
		t.Fatal("legacy view must be observe-only")
	}
	if len(node.Binding.GroupIDs) != 1 || node.Binding.GroupIDs[0] != "sg-legacy-node-a" {
		t.Fatalf("bad binding groups: %v", node.Binding.GroupIDs)
	}
	if len(node.Binding.ZoneIDs) != 0 {
		t.Fatalf("legacy binding must not trust zones: %v", node.Binding.ZoneIDs)
	}
	zoneIfaces := map[string][]string{}
	zoneCIDRs := map[string][]string{}
	for _, z := range node.Zones {
		zoneIfaces[z.ID] = z.Interfaces
		zoneCIDRs[z.ID] = z.CIDRs
	}
	if got := zoneIfaces["public"]; len(got) != 1 || got[0] != "ens3" {
		t.Fatalf("public zone interfaces = %v", got)
	}
	if got := zoneCIDRs["wireguard"]; len(got) != 1 || got[0] != "10.66.0.0/24" {
		t.Fatalf("wireguard zone cidrs = %v", got)
	}

	groupsRes := doJSON(t, handler, http.MethodGet, "/api/netguard/groups", "", cookies, csrf)
	defer groupsRes.Body.Close()
	if groupsRes.StatusCode != http.StatusOK {
		t.Fatalf("netguard groups failed: %d", groupsRes.StatusCode)
	}
	var groups netGuardGroupsResponse
	if err := json.NewDecoder(groupsRes.Body).Decode(&groups); err != nil {
		t.Fatal(err)
	}
	if len(groups.Groups) != 1 {
		t.Fatalf("want 1 legacy group, got %d", len(groups.Groups))
	}
	group := groups.Groups[0]
	if group.ID != "sg-legacy-node-a" || group.Source != "legacy" || group.NodeID != "node-a" {
		t.Fatalf("bad group view: %+v", group)
	}
	if len(group.Rules) != 2 {
		t.Fatalf("want tcp+udp rules, got %d", len(group.Rules))
	}
	tcp := group.Rules[0]
	if tcp.Protocol != "tcp" || tcp.Remote.Kind != "zone" || tcp.Remote.ZoneID != "public" {
		t.Fatalf("bad tcp rule: %+v", tcp)
	}
	// 22 stays single, 9009-9013 collapses into one reviewable range.
	if len(tcp.Ports) != 2 || tcp.Ports[0].From != 22 || tcp.Ports[0].To != 22 ||
		tcp.Ports[1].From != 9009 || tcp.Ports[1].To != 9013 {
		t.Fatalf("bad tcp ranges: %+v", tcp.Ports)
	}

	// The legacy view must not have persisted anything.
	if _, ok := st.SecurityGroup("sg-legacy-node-a"); ok {
		t.Fatal("legacy conversion must not write to the store")
	}
	if _, ok := st.NodeGuardBinding("node-a"); ok {
		t.Fatal("legacy conversion must not persist bindings")
	}

	zonesRes := doJSON(t, handler, http.MethodGet, "/api/netguard/zones", "", cookies, csrf)
	defer zonesRes.Body.Close()
	if zonesRes.StatusCode != http.StatusOK {
		t.Fatalf("netguard zones failed: %d", zonesRes.StatusCode)
	}
	var zones struct {
		Zones []struct {
			ID      string `json:"id"`
			Builtin bool   `json:"builtin"`
		} `json:"zones"`
	}
	if err := json.NewDecoder(zonesRes.Body).Decode(&zones); err != nil {
		t.Fatal(err)
	}
	builtins := map[string]bool{}
	for _, z := range zones.Zones {
		if z.Builtin {
			builtins[z.ID] = true
		}
	}
	for _, want := range []string{"public", "loopback", "wireguard", "tailscale"} {
		if !builtins[want] {
			t.Fatalf("builtin zone %q missing from %+v", want, zones.Zones)
		}
	}
}

func TestNetGuardStoredBindingSupersedesLegacyView(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[22]}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}

	group, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-web", Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{
		NodeID:   "node-a",
		GroupIDs: []string{group.ID},
		Managed:  true,
	}); err != nil {
		t.Fatal(err)
	}

	nodesRes := doJSON(t, handler, http.MethodGet, "/api/netguard/nodes", "", cookies, csrf)
	defer nodesRes.Body.Close()
	var nodes netGuardNodesResponse
	if err := json.NewDecoder(nodesRes.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes.Nodes) != 1 {
		t.Fatalf("stored binding must supersede the legacy view, got %d views", len(nodes.Nodes))
	}
	if nodes.Nodes[0].Source != "stored" || !nodes.Nodes[0].Binding.Managed {
		t.Fatalf("bad stored view: %+v", nodes.Nodes[0])
	}
}

func TestNetGuardStoreVersionConflicts(t *testing.T) {
	_, st := newTestServer(t)

	created, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-a", Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 {
		t.Fatalf("first upsert version = %d, want 1", created.Version)
	}

	// Stale write (echoes version 0 after the record moved to 1) must fail.
	if _, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-a", Name: "clobber"}); !errors.Is(err, store.ErrGuardVersionConflict) {
		t.Fatalf("stale group upsert error = %v, want ErrGuardVersionConflict", err)
	}
	updated, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-a", Name: "a2", Version: created.Version})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || updated.Name != "a2" {
		t.Fatalf("bad updated group: %+v", updated)
	}

	binding, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Version != 1 {
		t.Fatalf("first binding version = %d, want 1", binding.Version)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a"}); !errors.Is(err, store.ErrGuardVersionConflict) {
		t.Fatalf("stale binding upsert error = %v, want ErrGuardVersionConflict", err)
	}
}
