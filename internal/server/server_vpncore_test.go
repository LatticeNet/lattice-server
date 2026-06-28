package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestVPNCoreNodesRPCRegisteredAndExports(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The in-core vpn-core/nodes service is registered with the export method.
	var found bool
	for _, d := range srv.pluginRPC.Services() {
		if d.Service == vpnCoreNodesService {
			found = true
			if len(d.Methods) != 1 || d.Methods[0] != "export" {
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

	// Unknown method is rejected by the handler.
	if _, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "nope", nil); err == nil {
		t.Fatalf("expected unknown-method error")
	}

	// The registry is wired into the broker host services so plugins can reach it.
	if srv.pluginHostServices().RPC == nil {
		t.Fatalf("HostServices.RPC not wired")
	}
}
