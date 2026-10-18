package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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

	// review compiles the node's intended state next to what it reports. An
	// unbound node compiles as an empty observe-only intent: the review runs,
	// says the intent cannot be compiled, and labels itself unbound, so the
	// plugin can show reality and suggestions before anyone adopts the node.
	unbound, err := srv.netGuardFirewallRPC(ctx, "review", []byte(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatalf("review of an unbound node: %v", err)
	}
	if !strings.Contains(string(unbound), `"source":"unbound"`) || !strings.Contains(string(unbound), `"compile_error":`) {
		t.Fatalf("unbound review must be labelled and carry the compile error: %s", unbound)
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

// The WireGuard page tells a node that never reported from one that went
// silent. It used to do that by reading year 1 out of last_seen, the only
// signal this view carried; now the view says it in status, by the node
// status rule, and an unset last_seen is left off the wire like every other
// optional time.
func TestWireGuardOverviewSaysNeverReportedWithoutYearOne(t *testing.T) {
	srv, st, ctx := newNetworkPluginRPCServer(t)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	for _, n := range []model.Node{
		{ID: "n-never", Name: "fresh-box", WireGuardIP: "10.9.0.1", WireGuardPublicKey: "k1"},
		{ID: "n-online", Name: "beating", Online: true, LastSeen: now.Add(-10 * time.Second)},
		{ID: "n-offline", Name: "flagged-off", Online: false, LastSeen: now.Add(-time.Hour)},
		// The sweep flipped the flag on a beat still inside the threshold: the
		// flag alone makes it offline.
		{ID: "n-flagged", Name: "flag-only", Online: false, LastSeen: now.Add(-time.Second)},
		// The liveness sweep has not flipped the flag yet, but the last beat is
		// past the threshold: the node status rule already says offline.
		{ID: "n-stale", Name: "stale-beat", Online: true, LastSeen: now.Add(-nodeOfflineThreshold - time.Second)},
		// Disabled outranks never reported.
		{ID: "n-disabled", Name: "switched-off", Disabled: true},
	} {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := srv.wireGuardNetworksRPC(ctx, "overview", nil)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if strings.Contains(string(raw), "0001-01-01") {
		t.Fatalf("overview carries year 1: %s", raw)
	}
	var out struct {
		Nodes []map[string]any `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	rows := map[string]map[string]any{}
	for _, row := range out.Nodes {
		id, _ := row["node_id"].(string)
		rows[id] = row
	}
	for id, want := range map[string]string{
		"n-never":    NodeStatusNeverReported,
		"n-online":   NodeStatusOnline,
		"n-offline":  NodeStatusOffline,
		"n-flagged":  NodeStatusOffline,
		"n-stale":    NodeStatusOffline,
		"n-disabled": NodeStatusDisabled,
	} {
		row, ok := rows[id]
		if !ok {
			t.Fatalf("%s is not listed: %s", id, raw)
		}
		if got := row["status"]; got != want {
			t.Errorf("%s: status = %v, want %s", id, got, want)
		}
	}
	for _, id := range []string{"n-never", "n-disabled"} {
		if seen, ok := rows[id]["last_seen"]; ok {
			t.Errorf("%s never reported, but last_seen is on the wire as %v", id, seen)
		}
	}
	if _, ok := rows["n-online"]["last_seen"].(string); !ok {
		t.Errorf("a node that reported lost last_seen: %v", rows["n-online"])
	}
	// online stays the stored flag for UIs that predate status.
	if rows["n-stale"]["online"] != true {
		t.Errorf("online must stay the stored flag: %v", rows["n-stale"])
	}
}
