package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestVPNCoreProfilesRPC(t *testing.T) {
	srv := newLinesTestServer(t)
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}
	// managed profile (applied) + collector health
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{
		ID: "prof-a", NodeID: "node-a", Core: "sing-box", InboundIDs: []string{"in-1", "in-2"},
		ConfigPath: "/etc/sing-box/config.json", AppliedSHA256: "abc",
		UsageCollectorSource: "file", UsageCollectorStatus: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	// discovered inventory for the same node + a discovery-only node
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok", CoreVersion: "1.12.12",
			Nodes: []model.SingBoxNode{{Name: "n1", Protocol: "vless"}, {Name: "n2", Protocol: "hysteria2"}}},
	}
	srv.singboxInvMu.Unlock()

	raw, err := srv.vpnCoreProfilesRPC(context.Background(), "query", nil)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var out struct {
		Profiles []NodeProfileRuntime `json:"profiles"`
		Count    int                  `json:"count"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count != 1 || len(out.Profiles) != 1 {
		t.Fatalf("want 1 node runtime, got %d", out.Count)
	}
	p := out.Profiles[0]
	if p.NodeID != "node-a" || !p.Managed || !p.Applied || p.CoreVersion != "1.12.12" ||
		p.InboundCount != 2 || p.DiscoveredCount != 2 || p.DiscoveryStatus != "ok" {
		t.Fatalf("runtime fields wrong: %+v", p)
	}
	if p.Collector == nil || p.Collector.Status != "ok" {
		t.Fatalf("collector missing: %+v", p.Collector)
	}
	// capabilities: probe + apply (managed) + discover (has inventory)
	caps := map[string]bool{}
	for _, c := range p.Capabilities {
		caps[c] = true
	}
	if !caps["probe"] || !caps["apply"] || !caps["discover"] {
		t.Fatalf("capabilities wrong: %v", p.Capabilities)
	}
	if _, err := srv.vpnCoreProfilesRPC(context.Background(), "bogus", nil); err == nil {
		t.Fatal("bogus method should error")
	}
}
