package server

import (
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
