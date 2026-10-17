package server

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A beacon path that has never had a reply reads beacon_filtered and can
// never page, so it is not a pending monitor.down either, exactly as an icmp
// path that never had an echo. Once a reply has come back, failures are
// failures and the next one is pending.
func TestNeverAnsweredBeaconPathIsNotPending(t *testing.T) {
	srv, handler, st := beaconFleet(t)
	enableBeacon(t, srv, handler, model.BeaconPlanRequest{})
	listenAsPlanned(t, srv, st)
	now := srv.now()
	bt, _ := st.BeaconTarget("node-t")
	for _, mon := range []model.Monitor{
		{ID: "mon-beacon", Name: "beacon", Type: model.MonitorTypeBeacon, Target: bt.Settings.Endpoint, TargetNode: "node-t", Packets: 3,
			IntervalSec: 60, TimeoutSec: 2, NodeIDs: []string{"node-a"}, Enabled: true, AlertAfter: 3},
		{ID: "mon-ping", Name: "ping", Type: model.MonitorTypeICMP, Target: "198.51.100.30", TargetNode: "node-t", Packets: 3,
			IntervalSec: 60, TimeoutSec: 2, NodeIDs: []string{"node-a"}, Enabled: true, AlertAfter: 3},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	allLost := func(monitorID string, at time.Time) model.MonitorResult {
		return model.MonitorResult{MonitorID: monitorID, NodeID: "node-a", At: at, Sent: 3, Lost: 3, Error: "no reply"}
	}
	ingest := func(results ...model.MonitorResult) {
		t.Helper()
		if resp, err := srv.ingestAgentMonitorResults("node-a", results); err != nil || resp.Accepted != len(results) {
			t.Fatalf("ingest = %+v %v", resp, err)
		}
	}
	pending := func(monitorID string) bool {
		for _, inc := range srv.pendingIncidents(now) {
			if inc.MonitorID == monitorID {
				return true
			}
		}
		return false
	}
	ingest(allLost("mon-beacon", now.Add(-2*time.Minute)), allLost("mon-ping", now.Add(-2*time.Minute)))
	m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, now)
	if err != nil {
		t.Fatal(err)
	}
	if c := pathCellFor(t, m, "node-a", "mon-beacon"); c.State != model.PathStateUnknown || c.Reason != model.PathReasonBeaconFiltered {
		t.Fatalf("never answered beacon path = %s %q", c.State, c.Reason)
	}
	for _, monitorID := range []string{"mon-beacon", "mon-ping"} {
		if pending(monitorID) {
			t.Errorf("%s never answered and is listed as a pending monitor.down that can never page", monitorID)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	ingest(model.MonitorResult{MonitorID: "mon-beacon", NodeID: "node-a", At: now.Add(-90 * time.Second), Success: true, Sent: 3, LatencyMs: 20, RTTsMs: []float64{20, 20, 20}})
	ingest(allLost("mon-beacon", now.Add(-time.Minute)))
	if !pending("mon-beacon") {
		t.Fatal("a beacon path that answered once and then failed is not pending")
	}
}

// Save errors name the kinds the code accepts: packets on icmp and beacon
// checks (model.MonitorKindSendsPackets), a node target on icmp, tcp and
// beacon checks.
func TestCheckSaveErrorsNameTheKindsAccepted(t *testing.T) {
	_, handler, _ := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	for _, c := range []struct{ name, body, want string }{
		{"tcp with packets", `{"name":"t","type":"tcp","target":"example.com:443","packets":3,"node_ids":["node-new"]}`, "packets applies to icmp and beacon checks only"},
		{"http with packets", `{"name":"h","type":"http","target":"https://example.com/","packets":3,"node_ids":["node-new"]}`, "packets applies to icmp and beacon checks only"},
		{"http with a node", `{"name":"h","type":"http","target":"https://example.com/","target_node":"node-tgt","node_ids":["node-new"]}`, "target_node applies to icmp, tcp and beacon checks"},
	} {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors", c.body, cookies, csrf)
		body := readBody(t, res)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, c.want) {
			t.Errorf("%s = %d %s, want 400 naming %q", c.name, res.StatusCode, body, c.want)
		}
	}
	// The kinds the messages name are the kinds the code takes the field on.
	targets := monitorTargets{nodes: map[string]model.Node{"n": {ID: "n"}}}
	for _, kind := range []string{model.MonitorTypeTCP, model.MonitorTypeHTTP, model.MonitorTypeICMP, model.MonitorTypeBeacon, model.MonitorTypeTLS} {
		if named, sends := slices.Contains(monitorPacketKinds, kind), model.MonitorKindSendsPackets(kind); named != sends {
			t.Errorf("the packets error names %s: %v, but the kind sends packets: %v", kind, named, sends)
		}
		_, reason := targets.resolve(kind, "n", "")
		if named, resolved := slices.Contains(monitorNodeTargetKinds, kind), reason != "unsupported_kind"; named != resolved {
			t.Errorf("the target_node error names %s: %v, but the resolver takes the kind: %v", kind, named, resolved)
		}
	}
}
