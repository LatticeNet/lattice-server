package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
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

func vpnCoreProfileContext(scopes, allowlist []string) context.Context {
	p := principal{Principal: rbac.Principal{
		ActorID:         "profile-operator",
		Scopes:          scopes,
		ServerAllowlist: allowlist,
	}}
	return context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, p)
}

func TestVPNCoreProfileSettingsRequireExactNodeAuthorization(t *testing.T) {
	srv := newLinesTestServer(t)
	for _, nodeID := range []string{"node-a", "node-b"} {
		if err := srv.store.UpsertNode(model.Node{ID: nodeID, Name: strings.ToUpper(nodeID)}); err != nil {
			t.Fatal(err)
		}
	}
	payload := []byte(`{"node_id":"node-b"}`)
	if _, err := srv.vpnCoreProfilesRPC(context.Background(), "settings", payload); err == nil {
		t.Fatal("settings without an operator principal must fail closed")
	}
	restricted := vpnCoreProfileContext([]string{"node:read"}, []string{"node-a"})
	if _, err := srv.vpnCoreProfilesRPC(restricted, "settings", payload); err == nil {
		t.Fatal("node-a-restricted operator must not read node-b settings")
	}
	allowed, err := srv.vpnCoreProfilesRPC(restricted, "settings", []byte(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatalf("read allowed node settings: %v", err)
	}
	if !strings.Contains(string(allowed), `"node_id":"node-a"`) {
		t.Fatalf("unexpected settings result: %s", allowed)
	}
}

func TestVPNCoreProfileConfigurePreservesGenericLaunchAndNeverQueuesTask(t *testing.T) {
	srv := newLinesTestServer(t)
	launch := model.AgentLaunchConfig{
		AllowExec: true, AllowRootExec: true, AllowTerminal: true,
		TerminalTransport: "stream", SSHAlerts: true,
		SingBoxDiscover: false, SingBoxBin: "/usr/local/bin/sb-old",
	}
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", AgentLaunch: &launch}); err != nil {
		t.Fatal(err)
	}
	ctx := vpnCoreProfileContext([]string{"node:admin", "task:run"}, []string{"node-a"})
	raw, err := srv.vpnCoreProfilesRPC(ctx, "configure", []byte(`{
		"node_id":"node-a",
		"singbox_discover":true,
		"singbox_bin":"/usr/local/bin/sb",
		"proxy_usage_file":"/var/lib/sing-box/usage.json",
		"proxy_usage_url":"https://127.0.0.1:9090/stats",
		"proxy_usage_xray_api":"127.0.0.1:10085",
		"proxy_usage_xray_bin":"/usr/local/bin/xray",
		"proxy_usage_xray_pattern":"user>>>([^>]+)>>>traffic>>>(downlink|uplink)"
	}`))
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if !strings.Contains(string(raw), `"command"`) || !strings.Contains(string(raw), `"reconfigure_required":true`) {
		t.Fatalf("configure must return a reviewable command: %s", raw)
	}
	if strings.Contains(string(raw), "curl") || strings.Contains(string(raw), "raw.githubusercontent.com") {
		t.Fatalf("plugin configuration must not expose the unpinned installer path: %s", raw)
	}
	node, ok := srv.store.Node("node-a")
	if !ok || node.AgentLaunch == nil {
		t.Fatal("configured node missing")
	}
	got := *node.AgentLaunch
	if !got.AllowExec || !got.AllowRootExec || !got.AllowTerminal || got.TerminalTransport != "stream" || !got.SSHAlerts {
		t.Fatalf("generic launch settings were not preserved: %+v", got)
	}
	if !got.SingBoxDiscover || got.SingBoxBin != "/usr/local/bin/sb" || got.ProxyUsageFile == "" {
		t.Fatalf("plugin settings were not updated: %+v", got)
	}
	if tasks := srv.store.Tasks(); len(tasks) != 0 {
		t.Fatalf("saving plugin settings must not execute a host task: %+v", tasks)
	}
}

func TestVPNCoreProfileConfigureRejectsUnsafeInputsAndScopes(t *testing.T) {
	srv := newLinesTestServer(t)
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}
	adminOnly := vpnCoreProfileContext([]string{"node:admin"}, []string{"node-a"})
	if _, err := srv.vpnCoreProfilesRPC(adminOnly, "configure", []byte(`{"node_id":"node-a"}`)); err == nil {
		t.Fatal("configure requires task:run as well as node:admin")
	}
	ctx := vpnCoreProfileContext([]string{"node:admin", "task:run"}, []string{"node-a"})
	cases := []string{
		`{"node_id":"node-a","singbox_bin":"relative/sb"}`,
		`{"node_id":"node-a","proxy_usage_file":"/var/lib/../secret"}`,
		`{"node_id":"node-a","proxy_usage_url":"file:///etc/passwd"}`,
		`{"node_id":"node-a","proxy_usage_url":"https://user:pass@example.com/stats"}`,
	}
	for _, payload := range cases {
		if _, err := srv.vpnCoreProfilesRPC(ctx, "configure", []byte(payload)); err == nil {
			t.Fatalf("unsafe payload must fail: %s", payload)
		}
	}
}

func TestVPNCoreSubscriptionsRPCIsNotRegistered(t *testing.T) {
	srv := newLinesTestServer(t)
	for _, service := range srv.pluginRPC.Services() {
		if service.Service == "latticenet.vpn-core/subscriptions" {
			t.Fatalf("obsolete subscriptions service is still registered: %+v", service)
		}
	}
}
