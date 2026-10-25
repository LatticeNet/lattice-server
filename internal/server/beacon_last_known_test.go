package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// KI-34: line inventories live only in memory, so after a control-plane
// start no node has one until its agent reports again. A beacon applied on a
// provider edge must not read as nothing to dial in that window while the
// node's sing-box was last seen running; once the inventory is back, it is
// judged by the inventory again.

// edgeBeaconFleet is beaconFleet with node-t behind the provider edge
// 192.0.2.80 and its beacon applied on that edge, listening as planned.
func edgeBeaconFleet(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	srv, handler, st := beaconFleet(t)
	setEdgeInventory(srv, "192.0.2.80")
	resyncPaths(t, srv)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{Endpoint: "192.0.2.80:45000"})
	listenAsPlanned(t, srv, st)
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Method != model.MonitorTypeBeacon || !pair.Active {
		t.Fatalf("before the restart = %+v", pair)
	}
	return srv, st
}

// setEdgeInventory reports node-t's lines behind edge; an empty edge drops
// the edge line.
func setEdgeInventory(srv *Server, edge string) {
	inv := model.SingBoxInventory{NodeID: "node-t", At: srv.now(), Status: "ok", ProviderEdge: edge, Nodes: []model.SingBoxNode{
		{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: "198.51.100.30"},
	}}
	if edge != "" {
		inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "vless-edge", Protocol: "vless", Network: "reality", Port: "8443", PublicPort: "40443", ListenHost: "::"})
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv["node-t"] = inv
	srv.singboxInvMu.Unlock()
}

// forgetInventory is what a control-plane start leaves: no inventory for
// node-t until its agent reports.
func forgetInventory(srv *Server) {
	srv.singboxInvMu.Lock()
	delete(srv.singboxInv, "node-t")
	srv.singboxInvMu.Unlock()
}

func resyncPaths(t *testing.T, srv *Server) {
	t.Helper()
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
}

func noteSingBoxRunning(t *testing.T, srv *Server, st *store.Store, nodeID string) {
	t.Helper()
	if _, _, err := st.UpsertSingBoxLiveness(store.SingBoxLiveness{NodeID: nodeID, State: serviceStateRunning, StateSince: srv.now(), ReceivedAt: srv.now()}); err != nil {
		t.Fatal(err)
	}
}

func TestBeaconEdgeEndpointStandsUntilInventoryReturns(t *testing.T) {
	srv, st := edgeBeaconFleet(t)
	noteSingBoxRunning(t, srv, st, "node-t")

	forgetInventory(srv)
	resyncPaths(t, srv)
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Method != model.MonitorTypeBeacon || !pair.Active {
		t.Fatalf("after a start with no inventory yet = %+v", pair)
	}
	if reason := srv.beaconMonitorGate(nodeOf(t, st, "node-a"), "node-t", srv.now()); reason != "" {
		t.Fatalf("gate with no inventory yet = %q", reason)
	}
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-a"), srv.now()); cfg == nil || len(cfg.Keys) == 0 {
		t.Fatalf("the source lost the target key while inventory was missing: %+v", cfg)
	}

	// The inventory comes back without the edge: the node left it.
	setEdgeInventory(srv, "")
	resyncPaths(t, srv)
	if reason := srv.beaconMonitorGate(nodeOf(t, st, "node-a"), "node-t", srv.now()); reason != model.PathReasonNotProbeable {
		t.Fatalf("gate after the inventory dropped the edge = %q", reason)
	}
}

// The last-known rule needs evidence the node reports line inventory at all:
// without a sing-box record, or with the node offline, a missing inventory
// leaves only the node's own addresses, as before.
func TestBeaconEdgeEndpointNeedsARunningSingBoxAndAnOnlineNode(t *testing.T) {
	t.Run("no sing-box record", func(t *testing.T) {
		srv, st := edgeBeaconFleet(t)
		forgetInventory(srv)
		resyncPaths(t, srv)
		if reason := srv.beaconMonitorGate(nodeOf(t, st, "node-a"), "node-t", srv.now()); reason != model.PathReasonNotProbeable {
			t.Fatalf("gate = %q", reason)
		}
	})
	t.Run("node offline", func(t *testing.T) {
		srv, st := edgeBeaconFleet(t)
		noteSingBoxRunning(t, srv, st, "node-t")
		n := nodeOf(t, st, "node-t")
		n.Online = false
		upsertNodes(t, st, n)
		forgetInventory(srv)
		resyncPaths(t, srv)
		if reason := srv.beaconMonitorGate(nodeOf(t, st, "node-a"), "node-t", srv.now()); reason != model.PathReasonNotProbeable {
			t.Fatalf("gate = %q", reason)
		}
	})
}
