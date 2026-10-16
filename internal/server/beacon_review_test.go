package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Findings of the M2b security and Go reviews, one test each.

// A machine enrolled under the id of a deleted node inherits neither its
// source id nor its place in any approved set.
func TestBeaconDeletedNodeLeavesNoApprovalBehind(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	oldID := st.BeaconSourceIDs()["node-a"]
	if _, _, err := st.DeleteNode("node-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.BeaconSourceIDs()["node-a"]; ok {
		t.Fatal("a deleted node keeps its source id")
	}
	bt, _ := st.BeaconTarget("node-t")
	for _, src := range bt.Approved {
		if src.NodeID == "node-a" {
			t.Fatal("a deleted node stays in an approved set")
		}
	}
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "impostor", PublicIP: "203.0.113.66", Online: true, ProbeMethods: []string{"beacon", "http", "icmp", "tcp"}})
	saveBeaconPathSet(t, srv, st, model.LatencyProbeConfig{
		Enabled: true, Sources: []string{"node-a", "node-b", "node-c"}, IncludeTargets: []string{"node-t"}, Method: model.LatencyMethodAuto,
	})
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-a"), srv.now()); cfg != nil && len(cfg.Keys) > 0 {
		t.Fatalf("a machine under a recycled node id got a key: %+v", cfg.Keys)
	}
	ids, err := st.EnsureBeaconSourceIDs([]string{"node-a"})
	if err != nil || ids["node-a"] == oldID || ids["node-a"] == 0 {
		t.Fatalf("the new machine got source id %d (old %d): %v", ids["node-a"], oldID, err)
	}
}

// Reading a node.beacon approval needs monitor:read on every source it
// names, since it carries their addresses.
func TestBeaconApprovalReadNeedsTheSources(t *testing.T) {
	_, handler, _ := beaconFleet(t)
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable})
	if code != http.StatusOK {
		t.Fatalf("plan: %d %s", code, raw)
	}
	cookies, csrf := beaconLogin(t, handler)
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:read", "network:plan"}, []string{"node-t"})
	res := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", confined)
	if body := readBody(t, res); strings.Contains(body, out.Approval.ID) || strings.Contains(body, "203.0.113.21") {
		t.Fatalf("a token confined to the target read the plan and its sources' addresses: %s", body)
	}
	wide := createPAT(t, handler, cookies, csrf, []string{"monitor:read", "network:plan"}, nil)
	res = doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals", "", wide)
	if body := readBody(t, res); !strings.Contains(body, out.Approval.ID) {
		t.Fatalf("a token that reads every source does not see the plan: %s", body)
	}
}

// A node that moves off the address its plan advertises is no longer
// probed there: the address may belong to someone else now.
func TestBeaconEndpointFollowsTheNode(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Method != model.MonitorTypeBeacon {
		t.Fatalf("before the move = %+v", pair)
	}
	n := nodeOf(t, st, "node-t")
	n.PublicIP = "198.51.100.77"
	upsertNodes(t, st, n)
	srv.singboxInvMu.Lock()
	delete(srv.singboxInv, "node-t")
	srv.singboxInvMu.Unlock()
	srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
	if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
		t.Fatal(err)
	}
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Method == model.MonitorTypeBeacon && pair.Active {
		t.Fatalf("auto still probes the old address: %+v", pair)
	}
	if reason := srv.beaconMonitorGate(nodeOf(t, st, "node-a"), "node-t", srv.now()); reason != model.PathReasonNotProbeable {
		t.Fatalf("gate after the move = %q", reason)
	}
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-a"), srv.now()); cfg != nil && len(cfg.Keys) > 0 {
		t.Fatalf("a source still holds a key for an endpoint the node left: %+v", cfg.Keys)
	}
}

// A NetGuard companion that fails to apply leaves the beacon closed to
// sources (firewall pending), not live behind a rejected approval.
func TestBeaconCompanionFailureStaysClosed(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-t", Managed: true}); err != nil {
		t.Fatal(err)
	}
	srv.replaceAgentCapabilities("node-t", []string{netGuardManagedSHACapability})
	code, out, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable})
	if code != http.StatusOK {
		t.Fatalf("plan: %d %s", code, raw)
	}
	approved, err := decideBeacon(srv, out.Approval, beaconAdmin())
	if err != nil {
		t.Fatal(err)
	}
	task := tasksFor(srv, approved.ID)[0]
	if err := srv.handleBeaconTaskResult(httptestRequest(), approved, task, model.TaskResult{TaskID: task.ID, NodeID: "node-t", ExitCode: 1, Error: "nft: syntax error"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Approval(approved.ID); got.Status != model.ApprovalRejected {
		t.Fatalf("approval after a failed apply = %s", got.Status)
	}
	listenAsPlanned(t, srv, st)
	if bt, _ := st.BeaconTarget("node-t"); !bt.CompanionPending {
		t.Fatal("a failed companion no longer reads pending")
	}
	if cfg := srv.agentBeaconConfig(nodeOf(t, st, "node-a"), srv.now()); cfg != nil && len(cfg.Keys) > 0 {
		t.Fatalf("a source got a key behind a failed companion: %+v", cfg.Keys)
	}
	if pair := pairOf(t, srv.pathPlan(srv.now()), "node-a", "node-t"); pair.Method == model.MonitorTypeBeacon {
		t.Fatalf("auto chose a beacon whose firewall failed: %+v", pair)
	}
	if view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now()); !view.FirewallPending {
		t.Fatalf("view = %+v", view)
	}
}

// Two plans made from the same state: once one applies, the other is
// stale, whatever its bytes.
func TestBeaconSecondPlanFromTheSameBaseIsStale(t *testing.T) {
	srv, handler, _ := beaconFleet(t)
	_, first, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable, Port: 45001})
	if first.Approval.ID == "" {
		t.Fatalf("first plan: %s", raw)
	}
	_, second, raw := planBeacon(t, handler, model.BeaconPlanRequest{NodeID: "node-t", Action: model.BeaconActionEnable, Port: 45002})
	if second.Approval.ID == "" {
		t.Fatalf("second plan: %s", raw)
	}
	if _, err := decideBeacon(srv, first.Approval, beaconAdmin()); err != nil {
		t.Fatal(err)
	}
	if _, err := decideBeacon(srv, second.Approval, beaconAdmin()); err == nil {
		t.Fatal("a plan made before another applied was approved on top of it")
	}
}

// A reachability result from a source the check was not handed to decides
// nothing, and a sync after the verdict does not undo it.
func TestBeaconReachVerdictBelongsToItsSource(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	srv.syncBeaconReach(srv.now())
	mon, ok := st.Monitor(model.BeaconReachMonitorPrefix + "node-t")
	if !ok {
		t.Fatal("no reachability check")
	}
	source := mon.NodeIDs[0]
	other := "node-a"
	if source == other {
		other = "node-b"
	}
	srv.noteBeaconReachResult(model.MonitorResult{MonitorID: mon.ID, NodeID: other, Success: true}, srv.now())
	if bt, _ := st.BeaconTarget("node-t"); !bt.ReachArmed || bt.Reach.State != model.BeaconReachPending {
		t.Fatalf("another source decided the check: %+v", bt.Reach)
	}
	srv.noteBeaconReachResult(model.MonitorResult{MonitorID: mon.ID, NodeID: source, Success: true}, srv.now())
	srv.syncBeaconReach(srv.now())
	if bt, _ := st.BeaconTarget("node-t"); bt.ReachArmed || bt.Reach.State != model.BeaconReachReachable {
		t.Fatalf("a sync after the verdict changed it: %+v armed=%v", bt.Reach, bt.ReachArmed)
	}
}

// Reading a beacon writes nothing, and last_auth_at lives in memory only.
func TestBeaconReadsWriteNothing(t *testing.T) {
	srv, _, st := beaconFleet(t)
	view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-a"), srv.now())
	if view.State != model.BeaconStateOff {
		t.Fatalf("view = %+v", view)
	}
	if _, ok := st.BeaconTarget("node-a"); ok {
		t.Fatal("a read created beacon state")
	}
	seen := srv.now().Add(-time.Second)
	setBeaconFacts(t, srv, st, "node-t", model.BeaconFacts{Responder: true, State: model.BeaconAgentListening, Bind: "10.1.0.5", Port: 45000, LastAuthAt: seen})
	if stored := nodeOf(t, st, "node-t").Beacon; stored == nil || !stored.LastAuthAt.IsZero() {
		t.Fatalf("the node record keeps last_auth_at: %+v", stored)
	}
	if view := srv.beaconView(beaconAdmin(), nodeOf(t, st, "node-t"), srv.now()); !view.LastAuthAt.Equal(seen) {
		t.Fatalf("view last_auth_at = %v, want the reported %v", view.LastAuthAt, seen)
	}
	before := nodeOf(t, st, "node-t").Beacon
	setBeaconFacts(t, srv, st, "node-t", model.BeaconFacts{Responder: true, State: model.BeaconAgentListening, Bind: "10.1.0.5", Port: 45000, LastAuthAt: seen.Add(time.Hour)})
	if after := nodeOf(t, st, "node-t").Beacon; *after != *before {
		t.Fatal("a fresher last_auth_at rewrote the node record")
	}
}

// The icmp_filtered fallback is not forever: a day after the verdict, auto
// tries icmp again.
func TestAutoRetriesICMPAfterADay(t *testing.T) {
	srv, _, st := beaconFleet(t)
	icmpID := latencyICMPMonitorID("node-t")
	r := model.MonitorResult{MonitorID: icmpID, NodeID: "node-a", At: srv.now().Add(-time.Minute), Sent: 5, Lost: 5, Error: "all echoes lost"}
	if resp, err := srv.ingestAgentMonitorResults("node-a", []model.MonitorResult{r}); err != nil || resp.Accepted != 1 {
		t.Fatalf("ingest: %+v %v", resp, err)
	}
	plan := srv.planLatencyProbes(srv.now())
	if pair := pairOf(t, plan.plan, "node-a", "node-t"); pair.Method != model.MonitorTypeTCP {
		t.Fatalf("right after the verdict = %+v", pair)
	}
	plan = srv.planLatencyProbes(srv.now().Add(latencyICMPRecheck))
	if pair := pairOf(t, plan.plan, "node-a", "node-t"); pair.Method != model.MonitorTypeICMP {
		t.Fatalf("a day later auto still avoids icmp: %+v", pair)
	}
	_ = st
}

// The agent's error text loses its control characters.
func TestBeaconFactsDropControlCharacters(t *testing.T) {
	got := normalizeBeaconFacts(&model.BeaconFacts{Responder: true, Error: "bind:\x1b[31m in use\r\nforged line"}, time.Now())
	if strings.ContainsAny(got.Error, "\x1b\r\n") {
		t.Fatalf("error = %q", got.Error)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), `\u001b`) {
		t.Fatalf("json = %s", raw)
	}
	_ = store.BeaconTarget{}
}
