package server

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
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
	serverClock(t, srv2).set(beaconT0.Add(time.Minute))
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

// replanOf finds node-t in a matrix's replan list.
func replanOf(t *testing.T, srv *Server) *model.BeaconReplan {
	t.Helper()
	m, err := srv.pathMatrixFor(beaconAdmin(), model.PathWindowHour, srv.now())
	if err != nil {
		t.Fatal(err)
	}
	if m.BeaconReplans == nil {
		t.Fatal("the matrix carries no beacon_replans list")
	}
	for i := range m.BeaconReplans {
		if m.BeaconReplans[i].NodeID == "node-t" {
			return &m.BeaconReplans[i]
		}
	}
	return nil
}

// When a source is added to or removed from a NetGuard node's beacon, the
// beacon view and the matrix name the node that needs a change plan and the
// request that files it; sending that request as it is plans the current
// sources with the port, bind and endpoint unchanged, and once its approval
// applies nothing is pending. Nothing is filed or applied on its own.
func TestBeaconReplanNamesTheNodeAndThePlanRequest(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-t", Managed: true}); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-t", []string{netGuardManagedSHACapability})
	applyCompanion := func(approval model.Approval) {
		t.Helper()
		approved, err := decideBeacon(srv, approval, beaconAdmin())
		if err != nil {
			t.Fatal(err)
		}
		tasks := tasksFor(srv, approved.ID)
		if len(tasks) != 1 {
			t.Fatalf("tasks = %+v", tasks)
		}
		if err := srv.handleBeaconTaskResult(httptestRequest(), approved, tasks[0], model.TaskResult{TaskID: tasks[0].ID, NodeID: "node-t",
			Stdout: netGuardManagedSHAResultPrefix + strings.Repeat("ab", 32) + "\n", FinishedAt: srv.now()}); err != nil {
			t.Fatal(err)
		}
	}
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable})
	if code != 200 {
		t.Fatalf("enable = %d %s", code, raw)
	}
	applyCompanion(out.Approval)
	listenAsPlanned(t, srv, st)
	if r := replanOf(t, srv); r != nil {
		t.Fatalf("a beacon whose sources match its plan needs a replan: %+v", r)
	}
	if view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now()); view.Replan != nil {
		t.Fatalf("view replan = %+v", view.Replan)
	}
	applied, _ := st.BeaconTarget("node-t")

	// A source pinned to the beacon is added.
	upsertNodes(t, st, model.Node{ID: "node-d", Name: "delta", PublicIP: "203.0.113.24", Online: true, ProbeMethods: []string{"beacon", "http", "icmp", "tcp"}})
	listenAsPlanned(t, srv, st)
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-b", "node-c", "node-d"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
		SourceMethods: map[string]string{"node-d": model.LatencyMethodBeacon},
	})
	want := model.BeaconReplan{NodeID: "node-t", Name: "target", Reason: model.PathReasonFirewallPending, Added: []string{"node-d"}, Removed: []string{},
		Request: model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionChange}}
	r := replanOf(t, srv)
	if r == nil || string(mustJSON(t, *r)) != string(mustJSON(t, want)) {
		t.Fatalf("matrix replan = %+v, want %+v", r, want)
	}
	view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now())
	if view.Replan == nil || string(mustJSON(t, *view.Replan)) != string(mustJSON(t, want)) {
		t.Fatalf("view replan = %+v, want %+v", view.Replan, want)
	}
	if _, ok := st.Approval(applied.AppliedApprovalID); !ok || len(tasksFor(srv, applied.AppliedApprovalID)) != 1 {
		t.Fatal("the replan filed or applied something on its own")
	}
	// A token that may read every source but not the target learns nothing
	// about the target's beacon: not its id, name, reason or approval.
	sourcesOnly := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"monitor:read"}, ServerAllowlist: []string{"node-a", "node-b", "node-c", "node-d"}}}
	if m, err := srv.pathMatrixFor(sourcesOnly, model.PathWindowHour, srv.now()); err != nil || m.BeaconReplans == nil || len(m.BeaconReplans) != 0 {
		t.Fatalf("a token that cannot read node-t reads beacon_replans %+v (%v)", m.BeaconReplans, err)
	}

	// One click: the request as it is.
	code, out, raw = planBeacon(t, handler, r.Request)
	if code != 200 {
		t.Fatalf("the replan request = %d %s", code, raw)
	}
	if out.Plan.Beacon.Port != applied.Settings.Port || out.Plan.Beacon.Bind != applied.Settings.Bind || out.Plan.Beacon.Endpoint != applied.Settings.Endpoint {
		t.Fatalf("the replan moved the beacon: %+v, applied %+v", out.Plan.Beacon, applied.Settings)
	}
	var planned []string
	for _, src := range out.Plan.Sources {
		planned = append(planned, src.NodeID)
	}
	if !slices.Equal(planned, []string{"node-a", "node-b", "node-d"}) || out.Plan.NetGuard == nil || !slices.Contains(out.Plan.NetGuard.Allow, "203.0.113.24/32") {
		t.Fatalf("the replan's sources = %v, allow %+v", planned, out.Plan.NetGuard)
	}
	if r := replanOf(t, srv); r == nil || r.PendingApprovalID != out.Approval.ID {
		t.Fatalf("while the plan waits the replan = %+v, want it to name approval %s", r, out.Approval.ID)
	}
	applyCompanion(out.Approval)
	if r := replanOf(t, srv); r != nil {
		t.Fatalf("after the plan applied the replan = %+v", r)
	}

	// A source leaves: NetGuard still admits it until a plan.
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-b", "node-c", "node-d"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
		SourceMethods: map[string]string{"node-d": model.LatencyMethodBeacon},
	})
	if r := replanOf(t, srv); r == nil || r.Reason != model.PathReasonFirewallPending || len(r.Added) != 0 || !slices.Equal(r.Removed, []string{"node-a"}) {
		t.Fatalf("after node-a left the replan = %+v", r)
	}
	// A token that may not read node-a learns a plan is needed, not who left.
	confined := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"monitor:read"}, ServerAllowlist: []string{"node-t", "node-b", "node-d"}}}
	if view := srv.beaconView(confined, nodeOf(t, st, "node-t"), srv.now()); view.Replan == nil || len(view.Replan.Removed) != 0 {
		t.Fatalf("confined view replan = %+v", view.Replan)
	}
}

// Without NetGuard an added source waits for its approval and a source that
// leaves needs no plan: the table drops it at the target's next pull.
func TestBeaconReplanWithoutNetGuard(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-b", "node-c"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
	})
	if r := replanOf(t, srv); r != nil {
		t.Fatalf("a source that left an internet beacon needs a replan: %+v", r)
	}
	upsertNodes(t, st, model.Node{ID: "node-d", Name: "delta", PublicIP: "203.0.113.24", Online: true, ProbeMethods: []string{"beacon", "http", "icmp", "tcp"}})
	listenAsPlanned(t, srv, st)
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-b", "node-c", "node-d"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
		SourceMethods: map[string]string{"node-d": model.LatencyMethodBeacon},
	})
	r := replanOf(t, srv)
	if r == nil || r.Reason != model.PathReasonBeaconSourcePending || !slices.Equal(r.Added, []string{"node-d"}) || len(r.Removed) != 0 {
		t.Fatalf("an added source on an internet beacon = %+v", r)
	}
	if code, _, raw := planBeacon(t, handler, r.Request); code != 200 {
		t.Fatalf("the replan request = %d %s", code, raw)
	}
}
