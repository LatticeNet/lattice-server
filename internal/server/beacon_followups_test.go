package server

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A change plan that moves the beacon's port leaves the agent reporting
// listening before and after; its next report on the new port starts the
// reachability check the plan armed, as an enable's first listening report
// does.
func TestBeaconPortChangeStartsAReachabilityCheck(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	reach, ok := st.Monitor(model.BeaconReachMonitorPrefix + "node-t")
	if !ok {
		t.Fatal("the enable's reachability check did not start")
	}
	source := reach.NodeIDs[0]
	if _, err := srv.ingestAgentMonitorResults(source, []model.MonitorResult{{MonitorID: reach.ID, NodeID: source, At: srv.now().Add(-time.Second), Success: true, Sent: 3, LatencyMs: 20, RTTsMs: []float64{20, 20, 20}}}); err != nil {
		t.Fatal(err)
	}
	if bt, _ := st.BeaconTarget("node-t"); bt.ReachArmed || bt.Reach.State != model.BeaconReachReachable {
		t.Fatalf("after the first verdict reach = %+v armed=%v", bt.Reach, bt.ReachArmed)
	}
	old, _ := st.BeaconTarget("node-t")

	for _, c := range []struct {
		name string
		req  model.BeaconPlanRequest
	}{
		{"port", model.BeaconPlanRequest{Port: old.Settings.Port + 1}},
		{"bind", model.BeaconPlanRequest{Bind: "198.51.100.30"}},
	} {
		prior, _ := st.BeaconTarget("node-t")
		c.req.NodeID, c.req.Action = "node-t", model.BeaconActionChange
		code, out, raw := planBeacon(t, handler, c.req)
		if code != 200 {
			t.Fatalf("%s change plan = %d %s", c.name, code, raw)
		}
		if _, err := decideBeacon(srv, out.Approval, beaconAdmin()); err != nil {
			t.Fatalf("%s change approve: %v", c.name, err)
		}
		bt, _ := st.BeaconTarget("node-t")
		if !bt.ReachArmed || bt.Reach.State != model.BeaconReachPending {
			t.Fatalf("%s change: reach = %+v armed=%v", c.name, bt.Reach, bt.ReachArmed)
		}
		if _, ok := st.Monitor(model.BeaconReachMonitorPrefix + "node-t"); ok {
			t.Fatalf("%s change: the check started while the agent still listened on %s:%d", c.name, prior.Settings.Bind, prior.Settings.Port)
		}
		// The agent pulls the new config and reports listening where the
		// plan moved it: the state did not change, the port or bind did.
		setBeaconFacts(t, srv, st, "node-t", model.BeaconFacts{Responder: true, State: model.BeaconAgentListening, Bind: bt.Settings.Bind, Port: bt.Settings.Port})
		mon, ok := st.Monitor(model.BeaconReachMonitorPrefix + "node-t")
		if !ok || mon.ManagedBy != model.MonitorManagedBeacon || mon.Target != bt.Settings.Endpoint {
			t.Fatalf("%s change: no reachability check after the agent listened at %s:%d (%+v %v)", c.name, bt.Settings.Bind, bt.Settings.Port, mon, ok)
		}
		if _, err := srv.ingestAgentMonitorResults(mon.NodeIDs[0], []model.MonitorResult{{MonitorID: mon.ID, NodeID: mon.NodeIDs[0], At: srv.now().Add(-time.Second), Success: true, Sent: 3, LatencyMs: 20, RTTsMs: []float64{20, 20, 20}}}); err != nil {
			t.Fatal(err)
		}
		if bt, _ := st.BeaconTarget("node-t"); bt.ReachArmed || bt.Reach.State != model.BeaconReachReachable {
			t.Fatalf("%s change: verdict = %+v armed=%v", c.name, bt.Reach, bt.ReachArmed)
		}
	}
}

// A pending node.beacon approval renders the same document after a server
// restart. A NetGuard plan admits each source's egress address, which the
// server sees on the source's config pulls; after a restart, before a NAT
// source pulls again, the approval must not read stale for want of it.
func TestBeaconApprovalSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	srv, handler, st := newPathsServerAt(t, dir)
	seedBeaconFleet(t, srv, st)
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-t", Managed: true}); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-t", []string{netGuardManagedSHACapability})
	srv.noteBeaconEgress("node-b", "203.0.113.122") // a NAT source's real egress
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable})
	if code != 200 {
		t.Fatalf("plan = %d %s", code, raw)
	}
	if out.Plan.NetGuard == nil || !slices.Contains(out.Plan.NetGuard.Allow, "203.0.113.122/32") {
		t.Fatalf("the plan does not admit node-b's egress: %+v", out.Plan.NetGuard)
	}
	if _, err := srv.currentBeaconPlan(out.Approval, srv.now()); err != nil {
		t.Fatalf("before the restart: %v", err)
	}

	// Restart: a new server on what the first one wrote. node-t reconnects
	// (its agent capabilities are per connection); node-b has not pulled.
	srv.Close(context.Background())
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	srv2, _, st2 := newPathsServerAt(t, dir)
	srv2.now = func() time.Time { return beaconT0.Add(time.Minute) }
	srv2.replaceAgentCapabilities("node-t", []string{netGuardManagedSHACapability})
	approval, ok := st2.Approval(out.Approval.ID)
	if !ok || approval.Status != model.ApprovalPending {
		t.Fatalf("the approval after the restart = %+v %v", approval, ok)
	}
	if _, err := srv2.currentBeaconPlan(approval, srv2.now()); err != nil {
		t.Fatalf("after the restart the pending plan re-renders differently: %v", err)
	}
	if _, err := decideBeacon(srv2, approval, beaconAdmin()); err != nil {
		t.Fatalf("approve after the restart: %v", err)
	}
	if bt, _ := st2.BeaconTarget("node-t"); bt.Companion == nil || !slices.Contains(bt.Companion.Allow, "203.0.113.122/32") {
		t.Fatalf("the applied companion = %+v", bt.Companion)
	}
}
