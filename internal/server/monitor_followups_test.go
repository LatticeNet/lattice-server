package server

import (
	"encoding/json"
	"fmt"
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

// A create and an edit apply one alert_after rule: 0 means the default on
// both, and both refuse the same values with the same answer.
func TestAlertAfterZeroMeansTheDefaultOnCreateAndEdit(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"alert_after":0}`, cookies, csrf)
	created := decodeMonitorView(t, res)
	if res.StatusCode != http.StatusOK || created.AlertAfter != model.MonitorAlertAfterDefault {
		t.Fatalf("create with 0 = %d %+v", res.StatusCode, created)
	}
	res = doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+created.ID+`","version":1,"alert_after":5}`, cookies, csrf)
	if v := decodeMonitorView(t, res); res.StatusCode != http.StatusOK || v.AlertAfter != 5 {
		t.Fatalf("edit to 5 = %d %+v", res.StatusCode, v)
	}
	res = doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+created.ID+`","version":2,"alert_after":0}`, cookies, csrf)
	edited := decodeMonitorView(t, res)
	if res.StatusCode != http.StatusOK || edited.AlertAfter != model.MonitorAlertAfterDefault || edited.Version != 3 {
		t.Fatalf("edit back to 0 = %d %+v; a create takes 0 as the default and an edit must too", res.StatusCode, edited)
	}
	for _, bad := range []string{"-1", "21"} {
		create := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"y","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"alert_after":`+bad+`}`, cookies, csrf)
		createBody := readBody(t, create)
		edit := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+created.ID+`","version":3,"alert_after":`+bad+`}`, cookies, csrf)
		editBody := readBody(t, edit)
		message := func(body string) string {
			var out struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			_ = json.Unmarshal([]byte(body), &out)
			return out.Error.Message
		}
		if create.StatusCode != http.StatusBadRequest || edit.StatusCode != http.StatusBadRequest || message(createBody) != message(editBody) ||
			!strings.Contains(message(createBody), "or 0 for the default") {
			t.Fatalf("alert_after %s: create %d %s, edit %d %s", bad, create.StatusCode, createBody, edit.StatusCode, editBody)
		}
	}
}

// The timeout bound a save enforces is 60 s, model.MonitorTimeoutMaxSec, the
// constant the console mirrors: a create and an edit of every agent kind and
// a tls check take 60 and refuse 61 with an answer naming the bound.
func TestCheckTimeoutBoundIsTheSDKs(t *testing.T) {
	if model.MonitorTimeoutMaxSec != 60 {
		t.Fatalf("model.MonitorTimeoutMaxSec = %d, want 60", model.MonitorTimeoutMaxSec)
	}
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	want := fmt.Sprintf("timeout_sec must be 1 to %d", model.MonitorTimeoutMaxSec)
	for _, c := range []struct{ kind, target, nodes string }{
		{"tcp", "203.0.113.9:443", `"node_ids":["node-a"],`},
		{"http", "https://example.com/", `"node_ids":["node-a"],`},
		{"tls", "example.com:443", ""},
	} {
		body := func(timeout int) string {
			return fmt.Sprintf(`{"name":"x","type":%q,"target":%q,%s"interval_sec":120,"timeout_sec":%d}`, c.kind, c.target, c.nodes, timeout)
		}
		over := doJSON(t, handler, http.MethodPost, "/api/monitors", body(model.MonitorTimeoutMaxSec+1), cookies, csrf)
		if text := readBody(t, over); over.StatusCode != http.StatusBadRequest || !strings.Contains(text, want) {
			t.Fatalf("%s create at %d s = %d %s", c.kind, model.MonitorTimeoutMaxSec+1, over.StatusCode, text)
		}
		at := doJSON(t, handler, http.MethodPost, "/api/monitors", body(model.MonitorTimeoutMaxSec), cookies, csrf)
		created := decodeMonitorView(t, at)
		if at.StatusCode != http.StatusOK || created.TimeoutSec != model.MonitorTimeoutMaxSec {
			t.Fatalf("%s create at %d s = %d %+v", c.kind, model.MonitorTimeoutMaxSec, at.StatusCode, created)
		}
		edit := doJSON(t, handler, http.MethodPost, "/api/monitors/update", fmt.Sprintf(`{"id":%q,"version":1,"timeout_sec":%d}`, created.ID, model.MonitorTimeoutMaxSec+1), cookies, csrf)
		if text := readBody(t, edit); edit.StatusCode != http.StatusBadRequest || !strings.Contains(text, want) {
			t.Fatalf("%s edit to %d s = %d %s", c.kind, model.MonitorTimeoutMaxSec+1, edit.StatusCode, text)
		}
	}
}

// A window of N buckets counts N. A check that ran every minute, its newest
// run stamped exactly now, reads 60 of 60 in the 1h matrix (not 61 of 60:
// the window used to hold both ends) and 1440 of 1440 in the 24h matrix
// (not the bucket in progress on top). Its 1h series is 60 one-minute
// buckets, the last in progress, which expects the run it already heard
// rather than reading 1 of 0; a step in progress that heard nothing reads a
// gap only once a whole interval has passed in it.
func TestPathWindowsCountTheirBuckets(t *testing.T) {
	srv, _, st := newPathsServer(t)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a", Online: true})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-a", Name: "a", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var runs []model.MonitorResult
	for i := 25 * 60; i >= 0; i-- {
		runs = append(runs, model.MonitorResult{MonitorID: "mon-a", At: now.Add(-time.Duration(i) * time.Minute), Success: true, LatencyMs: 20})
	}
	if _, err := st.IngestAgentMonitorResults("node-a", runs, now); err != nil {
		t.Fatal(err)
	}
	p := principal{Principal: adminPrincipalForTest()}
	for _, c := range []struct {
		window string
		want   int
	}{{model.PathWindowHour, 60}, {model.PathWindowDay, 1440}} {
		m, err := srv.pathMatrixFor(p, c.window, now)
		if err != nil {
			t.Fatal(err)
		}
		if cell := pathCellFor(t, m, "node-a", "mon-a"); cell.Samples != c.want || cell.Expected != c.want {
			t.Errorf("%s matrix = %d samples of %d expected, want %d of %d", c.window, cell.Samples, cell.Expected, c.want, c.want)
		}
	}
	checks := []pathCheck{{monitorID: "mon-a", method: model.MonitorTypeTCP}}
	series, err := srv.pathSeriesFor(checks, "node-a", model.PathWindowHour, time.Minute, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(series.Buckets) != 60 || !series.From.Equal(now.Add(-59*time.Minute)) {
		t.Fatalf("1h series = %d buckets from %s, want 60 from %s", len(series.Buckets), series.From, now.Add(-59*time.Minute))
	}
	for i, b := range series.Buckets {
		if b.N != 1 || b.Expected != 1 {
			t.Errorf("1h series bucket %d at %s = %d of %d, want 1 of 1", i, b.T.Format(time.TimeOnly), b.N, b.Expected)
		}
	}
	// Five-minute steps, read three minutes into a step that heard nothing
	// (the check stopped at now): three runs were due, so it is a gap. Read
	// thirty seconds into one, nothing was certainly due yet.
	for _, c := range []struct {
		at   time.Duration
		want int
	}{{3 * time.Minute, 3}, {30 * time.Second, 0}} {
		six, err := srv.pathSeriesFor(checks, "node-a", model.PathWindowSixHours, time.Minute, now.Add(5*time.Minute+c.at))
		if err != nil {
			t.Fatal(err)
		}
		last := six.Buckets[len(six.Buckets)-1]
		if len(six.Buckets) != 72 || last.N != 0 || last.Expected != c.want {
			t.Errorf("6h series %s into an empty step: %d buckets, last %d of %d, want 72 and 0 of %d", c.at, len(six.Buckets), last.N, last.Expected, c.want)
		}
	}
}
