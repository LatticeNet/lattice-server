package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A check's alert_after sets how many failures in a row page and read as
// down: the pending incident covers the failures before that, the page goes
// out on the last of them, and the matrix reads down from there.
func TestMonitorAlertAfterDecidesThePageAndTheState(t *testing.T) {
	srv, _, st := newPathsServer(t)
	now := time.Now().UTC()
	serverClock(t, srv).set(now)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a", Online: true, LastSeen: now})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-3", Name: "three", Type: model.MonitorTypeTCP, Target: "203.0.113.4:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true, AlertAfter: 3}); err != nil {
		t.Fatal(err)
	}
	key := incidentKey(EventMonitorDown, "node-a", "mon-3")
	p := principal{Principal: adminPrincipalForTest()}
	for i := 1; i <= 3; i++ {
		at := now.Add(-time.Duration(4-i) * time.Minute)
		out, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-3", At: at, Success: false, Error: "refused"}}, now)
		if err != nil || !out[0].Stored() {
			t.Fatalf("ingest %d = %+v %v", i, out, err)
		}
		srv.notifyMonitorTransition("node-a", out[0].Result.MonitorResult, out[0].PriorFailStreak)
		_, open := st.ActiveIncident(key)
		pending := false
		for _, inc := range srv.pendingIncidents(now) {
			if inc.MonitorID == "mon-3" {
				pending = true
			}
		}
		m, err := srv.pathMatrixFor(p, model.PathWindowHour, now)
		if err != nil {
			t.Fatal(err)
		}
		state := pathCellFor(t, m, "node-a", "mon-3").State
		switch i {
		case 1, 2:
			if open || !pending || state != model.PathStateUp {
				t.Fatalf("after %d of 3 failures: open %v pending %v state %s", i, open, pending, state)
			}
		case 3:
			if !open || pending || state != model.PathStateDown {
				t.Fatalf("after 3 of 3 failures: open %v pending %v state %s", open, pending, state)
			}
		}
	}
}

// alert_after is bounded on create and on edit and shows in the list.
func TestMonitorAlertAfterIsValidated(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	for body, want := range map[string]int{
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"alert_after":21}`:               http.StatusBadRequest,
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"alert_after":-1}`:               http.StatusBadRequest,
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"alert":"down","alert_after":4}`: http.StatusOK,
	} {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf)
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("create %s = %d, want %d", body, res.StatusCode, want)
		}
	}
	var id string
	for _, mon := range st.Monitors() {
		id = mon.ID
		if mon.AlertAfter != 4 {
			t.Fatalf("stored = %+v", mon)
		}
	}
	for body, want := range map[string]int{
		`{"id":"` + id + `","version":1,"alert_after":-1}`: http.StatusBadRequest,
		`{"id":"` + id + `","version":1,"alert_after":21}`: http.StatusBadRequest,
		`{"id":"` + id + `","version":1,"alert_after":1}`:  http.StatusOK,
	} {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors/update", body, cookies, csrf)
		if res.StatusCode != want {
			res.Body.Close()
			t.Fatalf("edit %s = %d, want %d", body, res.StatusCode, want)
		}
		if want == http.StatusOK {
			if v := decodeMonitorView(t, res); v.AlertAfter != 1 || v.Version != 2 {
				t.Fatalf("after the edit = %+v", v)
			}
			continue
		}
		res.Body.Close()
	}
}

// Disabling a check closes the incident it had open (no result will come to
// recover it) and keeps it out of the pending list.
func TestDisabledCheckClosesItsIncident(t *testing.T) {
	srv, _, st := newPathsServer(t)
	now := time.Now().UTC()
	serverClock(t, srv).set(now)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a", Online: true, LastSeen: now})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-x", Name: "x", Type: model.MonitorTypeTCP, Target: "203.0.113.4:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for i := 2; i >= 1; i-- {
		out, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-x", At: now.Add(-time.Duration(i) * time.Minute), Success: false, Error: "refused"}}, now)
		if err != nil {
			t.Fatal(err)
		}
		srv.notifyMonitorTransition("node-a", out[0].Result.MonitorResult, out[0].PriorFailStreak)
	}
	key := incidentKey(EventMonitorDown, "node-a", "mon-x")
	if _, ok := st.ActiveIncident(key); !ok {
		t.Fatal("two failures opened no incident")
	}
	mon, _ := st.Monitor("mon-x")
	mon.Enabled = false
	if _, err := st.UpdateMonitor(mon, mon.Version, now); err != nil {
		t.Fatal(err)
	}
	srv.evaluateIncidents(now)
	if _, ok := st.ActiveIncident(key); ok {
		t.Fatal("the incident of a disabled check stayed open")
	}
	// A disabled check with one failure on record is not pending either.
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-y", Name: "y", Type: model.MonitorTypeTCP, Target: "203.0.113.5:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-y", At: now.Add(-time.Minute), Success: false}}, now); err != nil {
		t.Fatal(err)
	}
	y, _ := st.Monitor("mon-y")
	y.Enabled = false
	if _, err := st.UpdateMonitor(y, y.Version, now); err != nil {
		t.Fatal(err)
	}
	for _, inc := range srv.pendingIncidents(now) {
		if inc.MonitorID == "mon-y" {
			t.Fatalf("a disabled check is pending: %+v", inc)
		}
	}
}

// Where the five-minute tier reaches back less far than the window but the
// hourly tier holds older history (a retention just raised, or the two days
// the previous release kept), the series reads the hourly tier instead of
// drawing that history as a gap.
func TestPathSeriesReadsTheHourlyTierWhileTheFineTierFills(t *testing.T) {
	srv, _, st := newPathsServer(t)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-a", Name: "a", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetMonitorSettings(model.MonitorSettings{FineRetentionDays: 3}, 0, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Stamped five days ago and received now: past the three-day fine line,
	// so only the hourly tier counts it.
	for _, at := range []time.Time{now.Add(-5 * 24 * time.Hour), now.Add(-time.Hour)} {
		if _, err := st.AddMonitorResult(model.MonitorResult{MonitorID: "mon-a", NodeID: "node-a", At: at, Success: true, LatencyMs: 20}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.SetMonitorSettings(model.MonitorSettings{FineRetentionDays: 7}, 1, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	checks := []pathCheck{{monitorID: "mon-a", method: model.MonitorTypeTCP}}
	week, err := srv.pathSeriesFor(checks, "node-a", model.PathWindowWeek, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	for _, b := range week.Buckets {
		runs += b.N
	}
	if week.StepSeconds != 3600 || runs != 2 {
		t.Fatalf("7d series while the fine tier fills: step %d, %d runs", week.StepSeconds, runs)
	}
	// The 24 h window is inside what the fine tier holds.
	day, err := srv.pathSeriesFor(checks, "node-a", model.PathWindowDay, time.Minute, now)
	if err != nil || day.StepSeconds != 300 {
		t.Fatalf("24h series: step %d %v", day.StepSeconds, err)
	}
}
