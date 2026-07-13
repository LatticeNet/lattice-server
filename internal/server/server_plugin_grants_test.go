package server

import (
	"context"
	"errors"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/plugin"
)

func TestPluginHostAccessIsMethodBoundAndRevocable(t *testing.T) {
	registry := plugin.NewRPCRegistry()
	if err := registry.Register("owner.plugin", "owner.plugin/items", "v1", []string{"list", "delete"},
		func(_ context.Context, method string, _ []byte) ([]byte, error) { return []byte(method), nil }); err != nil {
		t.Fatal(err)
	}
	srv := &Server{pluginRPC: registry}
	loaded := plugin.Loaded{Manifest: plugin.Manifest{
		ID: "caller.plugin",
		HostAccess: &plugin.HostAccessSpec{RPC: []plugin.RPCDependency{{
			Service: "owner.plugin/items", Methods: []string{"list"},
		}}},
	}}

	srv.applyPluginHostAccess(loaded)
	if out, err := registry.Call(context.Background(), "caller.plugin", "owner.plugin/items", "list", nil); err != nil || string(out) != "list" {
		t.Fatalf("declared host access failed: out=%q err=%v", out, err)
	}
	if _, err := registry.Call(context.Background(), "caller.plugin", "owner.plugin/items", "delete", nil); !errors.Is(err, plugin.ErrRPCDenied) {
		t.Fatalf("undeclared method must remain denied, got %v", err)
	}

	srv.revokePluginHostAccess(loaded)
	if _, err := registry.Call(context.Background(), "caller.plugin", "owner.plugin/items", "list", nil); !errors.Is(err, plugin.ErrRPCDenied) {
		t.Fatalf("disabled plugin grant must be revoked, got %v", err)
	}
}
