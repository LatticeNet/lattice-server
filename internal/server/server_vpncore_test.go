package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestVPNCoreExportIncludesDiscoveredNodes(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The nodes must exist (the export filters discovery to live nodes), as they
	// would when a real agent reports.
	for _, id := range []string{"node-a", "node-b"} {
		if err := st.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	// Inject a discovered inventory (as the agent report would).
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {NodeID: "node-a", Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "VLESS-REALITY-17891.json", ShareURL: "vless://a@h:17891#n1"},
			{Name: "Hysteria2-17892.json", ShareURL: "hysteria2://b@h:17892#n2"},
		}},
		// A node reporting a discovery error contributes a warning, no links.
		"node-b": {NodeID: "node-b", Status: "error", Error: "sb not found"},
	}
	srv.singboxInvMu.Unlock()

	call := func(body string) struct {
		Links    []string `json:"links"`
		Count    int      `json:"count"`
		Warnings []string `json:"warnings"`
	} {
		raw, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "export", []byte(body))
		if err != nil {
			t.Fatalf("export(%s): %v", body, err)
		}
		var out struct {
			Links    []string `json:"links"`
			Count    int      `json:"count"`
			Warnings []string `json:"warnings"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// Default (no body) includes discovered nodes.
	def := call("")
	if def.Count != 2 || len(def.Links) != 2 {
		t.Fatalf("default export should include 2 discovered links, got %+v", def)
	}
	hasWarn := false
	for _, w := range def.Warnings {
		if w != "" {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Fatalf("expected a discovery-error warning for node-b, got %+v", def.Warnings)
	}

	// include_discovered=false excludes them (empty managed store -> 0).
	off := call(`{"include_discovered":false}`)
	if off.Count != 0 {
		t.Fatalf("include_discovered=false should yield 0 links, got %+v", off)
	}

	// A user_id filter scopes to managed subscribers only (no discovered nodes);
	// unknown user errors rather than silently returning discovered links.
	if _, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "export", []byte(`{"user_id":"nope"}`)); err == nil {
		t.Fatalf("expected error for unknown user_id")
	}
}

func TestVPNCoreNodesRPCRegisteredAndExports(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The in-core vpn-core/nodes service is registered with the export + list
	// methods (list backs the design-10 plugin-contributed Nodes table; Services()
	// returns methods sorted, so the expected slice is ["export","list"]).
	var found bool
	for _, d := range srv.pluginRPC.Services() {
		if d.Service == vpnCoreNodesService {
			found = true
			if len(d.Methods) != 2 || d.Methods[0] != "export" || d.Methods[1] != "list" {
				t.Fatalf("unexpected methods: %+v", d.Methods)
			}
			if d.Owner != vpnCorePluginID {
				t.Fatalf("unexpected owner: %s", d.Owner)
			}
		}
	}
	if !found {
		t.Fatalf("vpn-core/nodes not registered: %+v", srv.pluginRPC.Services())
	}

	// Owner self-call export on an empty store -> empty, valid JSON envelope.
	out, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "export", nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var resp struct {
		Links []string `json:"links"`
		Count int      `json:"count"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if resp.Count != 0 || len(resp.Links) != 0 {
		t.Fatalf("expected empty export, got %+v", resp)
	}

	// list (the design-10 table data source) returns a valid, empty envelope on
	// an empty store — rows is a non-nil [] so the dashboard table renders cleanly.
	listOut, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "list", nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listResp struct {
		Rows  []map[string]any `json:"rows"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal(listOut, &listResp); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if listResp.Rows == nil {
		t.Fatalf("list rows must be non-nil JSON array, got null")
	}
	if listResp.Count != 0 || len(listResp.Rows) != 0 {
		t.Fatalf("expected empty list, got %+v", listResp)
	}

	// Unknown method is rejected by the handler.
	if _, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "nope", nil); err == nil {
		t.Fatalf("expected unknown-method error")
	}

	// The registry is wired into the broker host services so plugins can reach it.
	if srv.pluginHostServices().RPC == nil {
		t.Fatalf("HostServices.RPC not wired")
	}
}
