package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newNetworkPluginRPCServer(t *testing.T) (*Server, *store.Store, context.Context) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	p := principal{Principal: rbac.Principal{
		ActorID: "operator-test",
		Scopes:  []string{"node:read", "netguard:read", "netguard:admin", "network:plan"},
	}}
	return srv, st, context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, p)
}

func TestNetworkPluginRPCServicesAreOwnedByTheirPlugins(t *testing.T) {
	srv, _, _ := newNetworkPluginRPCServer(t)
	if !srv.pluginRPC.Owns(netGuardPluginID, netGuardFirewallService) {
		t.Fatal("NetGuard core service was not registered to the NetGuard plugin")
	}
	if !srv.pluginRPC.Owns(wireGuardPluginID, wireGuardNetworksService) {
		t.Fatal("WireGuard core service was not registered to the WireGuard plugin")
	}
}

func TestNetGuardRPCReusesValidationAndReturnsOverview(t *testing.T) {
	srv, _, ctx := newNetworkPluginRPCServer(t)
	created, err := srv.netGuardFirewallRPC(ctx, "upsert_group", []byte(`{"id":"sg-web","name":"Web","rules":[]}`))
	if err != nil {
		t.Fatalf("upsert group: %v", err)
	}
	if !strings.Contains(string(created), `"id":"sg-web"`) {
		t.Fatalf("unexpected group result: %s", created)
	}
	overview, err := srv.netGuardFirewallRPC(ctx, "overview", nil)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	var result struct {
		Groups []struct {
			ID string `json:"id"`
		} `json:"groups"`
		Zones []model.GuardZone `json:"zones"`
	}
	if err := json.Unmarshal(overview, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Groups) != 1 || result.Groups[0].ID != "sg-web" || len(result.Zones) < 4 {
		t.Fatalf("unexpected overview: %s", overview)
	}
	_, err = srv.netGuardFirewallRPC(ctx, "upsert_group", []byte(`{"id":"INVALID ID","name":"bad"}`))
	var operationErr *pluginOperationError
	if !errors.As(err, &operationErr) || operationErr.StatusCode != 400 {
		t.Fatalf("invalid group must preserve HTTP 400, got %v", err)
	}
}

func TestWireGuardRPCOverviewIsSecretFreeAndPlanCreatesApproval(t *testing.T) {
	srv, st, ctx := newNetworkPluginRPCServer(t)
	if err := st.UpsertNode(model.Node{
		ID: "node-a", Name: "Hong Kong", WireGuardIP: "10.66.0.1/32",
		WireGuardPublicKey: wgKey(1), WireGuardEndpoint: "203.0.113.7:51820", WireGuardPort: 51820,
	}); err != nil {
		t.Fatal(err)
	}
	overview, err := srv.wireGuardNetworksRPC(ctx, "overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(overview), `"configuration":"ready"`) || strings.Contains(strings.ToLower(string(overview)), "private_key") {
		t.Fatalf("unexpected or secret-bearing overview: %s", overview)
	}
	planned, err := srv.wireGuardNetworksRPC(ctx, "plan", []byte(`{"node_id":"node-a","listen_port":51820}`))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !strings.Contains(string(planned), `"plugin":"wireguard"`) || len(st.Approvals()) != 1 {
		t.Fatalf("plan did not create one WireGuard approval: result=%s approvals=%+v", planned, st.Approvals())
	}
}
