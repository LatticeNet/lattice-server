package server

import (
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A scope-limited operator must not be shown a subset that looks complete.
//
// `overview` filters its rows per node by wireguard:read, while a plan is
// compiled from every node in the store. So the config an operator approves can
// contain peers the view never listed. Reporting only the filtered count made
// the screen imply those rows were the whole mesh, and it under-reported in the
// direction that hides peers rather than inventing them.
//
// The unfiltered totals are counts, not identities. They let the view say
// "showing 12 of 35 mesh members" without naming a node the caller was not
// already entitled to list.

func TestWireGuardOverviewReportsUnfilteredMeshTotals(t *testing.T) {
	srv, st, ctx := newNetworkPluginRPCServer(t)
	for _, n := range []model.Node{
		{ID: "n1", Name: "alpha", WireGuardIP: "10.9.0.1", WireGuardPublicKey: "k1"},
		{ID: "n2", Name: "bravo", WireGuardIP: "10.9.0.2", WireGuardPublicKey: "k2"},
		// Half-configured: it counts toward the mesh but is not ready.
		{ID: "n3", Name: "charlie", WireGuardIP: "10.9.0.3"},
		// Not a mesh member at all, so it must not inflate the totals.
		{ID: "n4", Name: "delta"},
	} {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := srv.wireGuardNetworksRPC(ctx, "overview", nil)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	var out struct {
		Count     int `json:"count"`
		Ready     int `json:"ready"`
		MeshTotal int `json:"mesh_total"`
		MeshReady int `json:"mesh_ready"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	if out.MeshTotal != 3 {
		t.Fatalf("mesh_total must count every node carrying mesh identity, got %d want 3", out.MeshTotal)
	}
	if out.MeshReady != 2 {
		t.Fatalf("mesh_ready must count only nodes with both an address and a key, got %d want 2", out.MeshReady)
	}
	// An unrestricted principal sees everything, so the filtered and unfiltered
	// numbers agree here. The point of the pair is that they may diverge.
	if out.Count != 4 {
		t.Fatalf("an unrestricted principal should see every node row, got %d want 4", out.Count)
	}
	if out.Ready != out.MeshReady {
		t.Fatalf("ready %d and mesh_ready %d must agree for an unrestricted principal", out.Ready, out.MeshReady)
	}
}
