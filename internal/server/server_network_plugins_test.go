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
		Scopes:  []string{"node:read", "netguard:read", "netguard:admin", "network:plan", "wireguard:read", "wireguard:admin"},
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

// Design-13 D10: the WireGuard surface must not piggyback on fleet-wide
// node:read / network:plan. A principal holding those broad scopes but not the
// wireguard:* pair sees no nodes and cannot plan.
func TestWireGuardRPCRequiresWireGuardScopes(t *testing.T) {
	srv, st, _ := newNetworkPluginRPCServer(t)
	if err := st.UpsertNode(model.Node{
		ID: "node-a", Name: "Hong Kong", WireGuardIP: "10.66.0.1/32",
		WireGuardPublicKey: wgKey(1), WireGuardPort: 51820,
	}); err != nil {
		t.Fatal(err)
	}
	broad := principal{Principal: rbac.Principal{
		ActorID: "operator-broad",
		Scopes:  []string{"node:read", "network:plan"},
	}}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, broad)
	overview, err := srv.wireGuardNetworksRPC(ctx, "overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(overview), `"count":0`) {
		t.Fatalf("overview without wireguard:read must be empty, got %s", overview)
	}
	_, err = srv.wireGuardNetworksRPC(ctx, "plan", []byte(`{"node_id":"node-a","listen_port":51820}`))
	var operationErr *pluginOperationError
	if !errors.As(err, &operationErr) || operationErr.StatusCode != 403 {
		t.Fatalf("plan without wireguard:admin must be 403, got %v", err)
	}
	if len(st.Approvals()) != 0 {
		t.Fatalf("denied plan must not create approvals, got %+v", st.Approvals())
	}
}

func TestNetGuardRPCExposesReviewAndReality(t *testing.T) {
	srv, st, ctx := newNetworkPluginRPCServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}

	// reality without a node id is the fleet-wide list; the node the test just
	// created must appear in it even though it has never reported a snapshot,
	// because "no snapshot yet" is the state an operator most needs to see.
	list, err := srv.netGuardFirewallRPC(ctx, "reality", nil)
	if err != nil {
		t.Fatalf("reality list: %v", err)
	}
	var listed struct {
		Nodes []struct {
			NodeID         string `json:"node_id"`
			SnapshotStatus string `json:"snapshot_status"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(list, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Nodes) != 1 || listed.Nodes[0].NodeID != "node-a" {
		t.Fatalf("unexpected reality list: %s", list)
	}
	if listed.Nodes[0].SnapshotStatus == "" {
		t.Fatal("a node with no snapshot must still report a status")
	}

	// A node id narrows to the detail shape.
	detail, err := srv.netGuardFirewallRPC(ctx, "reality", []byte(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatalf("reality detail: %v", err)
	}
	if !strings.Contains(string(detail), `"node_id":"node-a"`) {
		t.Fatalf("unexpected reality detail: %s", detail)
	}

	// review compiles the node's intended state next to what it reports, so it
	// needs a binding to compile — an unbound node is a conflict, which is the
	// handler's own rule and stays that way through the RPC.
	if _, err := srv.netGuardFirewallRPC(ctx, "review", []byte(`{"node_id":"node-a"}`)); err == nil {
		t.Fatal("review of an unbound node must report the conflict")
	}
	if _, err := srv.netGuardFirewallRPC(ctx, "upsert_group", []byte(`{"id":"sg-web","name":"Web","rules":[]}`)); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := srv.netGuardFirewallRPC(ctx, "upsert_binding", []byte(`{"node_id":"node-a","group_ids":["sg-web"]}`)); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	review, err := srv.netGuardFirewallRPC(ctx, "review", []byte(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if len(review) == 0 {
		t.Fatal("review returned nothing")
	}

	// A missing node id is the handler's own error, surfaced as an operation
	// failure rather than silently reviewing some other node.
	if _, err := srv.netGuardFirewallRPC(ctx, "review", []byte(`{}`)); err == nil {
		t.Fatal("review without a node id must fail")
	}

	// An unknown node is not found, not a leak of whether it exists elsewhere.
	if _, err := srv.netGuardFirewallRPC(ctx, "review", []byte(`{"node_id":"missing"}`)); err == nil {
		t.Fatal("review of an unknown node must fail")
	}
}

func TestNetGuardReadRPCRequiresTheReadScope(t *testing.T) {
	srv, st, _ := newNetworkPluginRPCServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	// A principal with netguard:admin but not netguard:read must not reach the
	// read paths: the gateway checks the manifest's declared scopes, and the
	// handlers check their own, so a manifest mistake cannot widen either.
	narrow := principal{Principal: rbac.Principal{ActorID: "narrow", Scopes: []string{"netguard:admin"}}}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, narrow)
	if _, err := srv.netGuardFirewallRPC(ctx, "reality", nil); err == nil {
		t.Fatal("reality without netguard:read must be denied")
	}
	if _, err := srv.netGuardFirewallRPC(ctx, "review", []byte(`{"node_id":"node-a"}`)); err == nil {
		t.Fatal("review without netguard:read must be denied")
	}
}

// An operator scoped to one node cannot plan a mesh whose config would carry
// peers they are not allowed to see.
//
// overview filters its rows per node by wireguard:read, but a plan is compiled
// from every node in the store and the config it returns names each peer's
// public key, mesh IP and endpoint. So the same session was refused that data
// by one endpoint and handed it by another, which made the read filter
// decoration rather than a boundary.
//
// Refused rather than filtered on purpose: a mesh config that silently omits
// peers is a broken config, and an asymmetric mesh is worse than a clear error.
func TestWireGuardPlanRefusesPeersTheSessionCannotRead(t *testing.T) {
	srv, st, _ := newNetworkPluginRPCServer(t)
	for _, n := range []model.Node{
		{ID: "node-a", Name: "target", WireGuardIP: "10.66.0.1/32", WireGuardPublicKey: wgKey(1), WireGuardPort: 51820},
		{ID: "node-b", Name: "unreadable peer", WireGuardIP: "10.66.0.2/32", WireGuardPublicKey: wgKey(2), WireGuardPort: 51820},
	} {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	scoped := principal{Principal: rbac.Principal{
		ActorID:         "operator-scoped",
		Scopes:          []string{"node:read", "network:plan", "wireguard:read", "wireguard:admin"},
		ServerAllowlist: []string{"node-a"},
	}}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, scoped)

	_, err := srv.wireGuardNetworksRPC(ctx, "plan", []byte(`{"node_id":"node-a","listen_port":51820}`))
	var operationErr *pluginOperationError
	if !errors.As(err, &operationErr) || operationErr.StatusCode != 403 {
		t.Fatalf("planning a mesh containing an unreadable peer must be 403, got %v", err)
	}
	if strings.Contains(err.Error(), wgKey(2)) || strings.Contains(err.Error(), "node-b") {
		t.Fatalf("the refusal must not name what it is protecting: %v", err)
	}

	// The same operator, once every mesh member is within its allowlist, plans
	// normally. The check must gate on readability, not simply on being scoped.
	full := principal{Principal: rbac.Principal{
		ActorID:         "operator-full",
		Scopes:          []string{"node:read", "network:plan", "wireguard:read", "wireguard:admin"},
		ServerAllowlist: []string{"node-a", "node-b"},
	}}
	fullCtx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, full)
	if _, err := srv.wireGuardNetworksRPC(fullCtx, "plan", []byte(`{"node_id":"node-a","listen_port":51820}`)); err != nil {
		t.Fatalf("an operator who can read every mesh member must still be able to plan: %v", err)
	}
}
