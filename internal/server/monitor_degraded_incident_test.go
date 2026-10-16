package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func pathPair(monitorID string) store.MonitorPair {
	return store.MonitorPair{MonitorID: monitorID, NodeID: "node-sh"}
}

// runsFor gives every pair the same run.
func runsFor(r model.MonitorResult, pairs ...store.MonitorPair) map[store.MonitorPair]model.MonitorResult {
	out := make(map[store.MonitorPair]model.MonitorResult, len(pairs))
	for _, p := range pairs {
		out[p] = r
	}
	return out
}

// slowFixture is a fixture whose checks each hold a week at 40 ms and an
// hour at 100 ms from node-sh: every one is found degraded on its latency.
func slowFixture(t *testing.T, dir string, ids ...string) *degradedFixture {
	t.Helper()
	var history []store.MonitorResultRecord
	for _, id := range ids {
		history = append(history, baselineHistory(id, "node-sh", degradedBase, 168, 40)...)
		history = append(history, windowRuns(id, "node-sh", degradedBase, slowRuns)...)
	}
	return openDegradedFixture(t, dir, history)
}

// clearUntilLeft reports fast runs for pairs a minute at a time until every
// one has left, and returns how many minutes that took.
func (f *degradedFixture) clearUntilLeft(pairs ...store.MonitorPair) int {
	f.t.Helper()
	for i := 1; i <= 40; i++ {
		f.tick(runsFor(okRun(40), pairs...))
		recs, err := f.st.PathDegradedRecords()
		if err != nil {
			f.t.Fatal(err)
		}
		left := true
		for _, p := range pairs {
			if _, held := recs[p]; held {
				left = false
			}
		}
		if left {
			return i
		}
	}
	f.t.Fatal("the paths never left")
	return 0
}

// path.degraded pages only under down_and_degraded, once per episode whatever
// the evaluations in between, with the evidence; the recovery follows the
// open that was sent; a degradation within 30 minutes reopens the same record
// as a flap.
func TestPathDegradedPagesOnlyUnderDownAndDegraded(t *testing.T) {
	f := slowFixture(t, t.TempDir(), "mon-down", "mon-dd")
	f.operatorCheck("mon-down", model.MonitorAlertDown, nil, "node-sh")
	f.operatorCheck("mon-dd", model.MonitorAlertDownAndDegraded, nil, "node-sh")
	both := []store.MonitorPair{pathPair("mon-down"), pathPair("mon-dd")}
	f.evaluate()
	expectNotices(t, "after one finding", f.sweep())
	f.tick(runsFor(okRun(100), both...))
	got := f.sweep()
	expectNotices(t, "after entering", got, "path.degraded: Path degraded: mon-dd on cd-hs-sh")
	if !strings.Contains(got[0].body, "Median 100 ms over the last 15 minutes") || !strings.Contains(got[0].body, "above its trigger of 80 ms (7-day median 40 ms)") ||
		!strings.Contains(got[0].body, "Degraded since 12:50 UTC.") {
		t.Fatalf("open body = %q", got[0].body)
	}
	inc, ok := f.st.ActiveIncident(pathDegradedKey(pathPair("mon-dd")))
	if !ok || inc.Kind != EventPathDegraded || inc.Severity != incidentSeverityWarning || inc.NodeID != "node-sh" || inc.MonitorID != "mon-dd" ||
		inc.Subject != "mon-dd on cd-hs-sh" || !inc.Since.Equal(degradedBase) {
		t.Fatalf("incident = %+v", inc)
	}
	if _, open := f.st.ActiveIncident(pathDegradedKey(pathPair("mon-down"))); open {
		t.Fatal("a check on down opened path.degraded")
	}
	for i := 0; i < 3; i++ {
		f.tick(runsFor(okRun(100), both...))
	}
	expectNotices(t, "while it stays degraded", f.sweep())
	f.clearUntilLeft(both...)
	got = f.sweep()
	expectNotices(t, "after leaving", got, "path.recovered: Path recovered: mon-dd on cd-hs-sh")
	if !strings.Contains(got[0].body, "Back to its usual level since") {
		t.Fatalf("recovery body = %q", got[0].body)
	}
	// Slow again within 30 minutes: the same record reopens, one flap.
	for i := 0; i < 16; i++ {
		f.tick(runsFor(okRun(100), both...))
	}
	expectNotices(t, "degraded again", f.sweep(), "path.degraded: Path degraded: mon-dd on cd-hs-sh")
	again, ok := f.st.ActiveIncident(pathDegradedKey(pathPair("mon-dd")))
	if !ok || again.ID != inc.ID || again.Flaps != 1 {
		t.Fatalf("reopened = %+v, first %s", again, inc.ID)
	}
}

// A record that entered while the path read down is quiet for its episode:
// the outage's hour of loss pages nothing once the path is back up.
func TestPathDegradedFromAnOutageStaysQuiet(t *testing.T) {
	var history []store.MonitorResultRecord
	history = append(history, baselineHistory("mon-dd", "node-sh", degradedBase, 168, 40)...)
	history = append(history, windowRuns("mon-dd", "node-sh", degradedBase, func(i int) (bool, float64) {
		return i < 40 && i%10 != 0, 40 // lossy, then down for the last twenty runs
	})...)
	f := openDegradedFixture(t, t.TempDir(), history)
	f.operatorCheck("mon-dd", model.MonitorAlertDownAndDegraded, nil, "node-sh")
	pair := pathPair("mon-dd")
	f.evaluate()
	f.tick(runsFor(failedRun, pair))
	recs, _ := f.st.PathDegradedRecords()
	if rec, held := recs[pair]; !held || !rec.Quiet {
		t.Fatalf("entered during the outage: %+v", recs)
	}
	for i := 0; i < 5; i++ {
		f.tick(runsFor(okRun(40), pair))
	}
	if c := pathCellFor(t, f.matrix(), "node-sh", "mon-dd"); c.State != model.PathStateDegraded {
		t.Fatalf("back up with the outage's loss in the hour: %+v", c)
	}
	for _, n := range f.sweep() {
		if n.eventType == EventPathDegraded {
			t.Fatalf("an outage-made record paged: %+v", n)
		}
	}
	if _, open := f.st.ActiveIncident(pathDegradedKey(pair)); open {
		t.Fatal("an outage-made record opened path.degraded")
	}
}

// A record that enters and leaves before any sweep sent its open owes no
// recovery: the phone never heard it was degraded.
func TestPathDegradedRecoveryOnlyAfterTheOpenWasSent(t *testing.T) {
	f := slowFixture(t, t.TempDir(), "mon-dd")
	f.operatorCheck("mon-dd", model.MonitorAlertDownAndDegraded, nil, "node-sh")
	pair := pathPair("mon-dd")
	f.evaluate()
	f.tick(runsFor(okRun(100), pair))
	if _, open := f.st.ActiveIncident(pathDegradedKey(pair)); !open {
		t.Fatal("no incident opened")
	}
	f.clearUntilLeft(pair)
	expectNotices(t, "an episode nobody was told about", f.sweep())
	inc, ok := f.st.LatestIncident(pathDegradedKey(pair))
	if !ok || inc.Active() || inc.OwedRecovery || inc.Notified != "" {
		t.Fatalf("incident = %+v", inc)
	}
}

// A policy change, a pause and a removed source close an open path.degraded
// with a message that says why, in place of a recovery.
func TestPathDegradedClosesWithoutARecovery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(m *model.Monitor)
		title  string
	}{
		{"policy", func(m *model.Monitor) { m.Alert = model.MonitorAlertDown }, "path.recovered: Degraded alerts off for mon-dd on cd-hs-sh"},
		{"pause", func(m *model.Monitor) { m.PausedNodeIDs = []string{"node-sh"} }, "path.recovered: Path no longer checked: mon-dd on cd-hs-sh"},
		{"removed source", func(m *model.Monitor) { m.NodeIDs = []string{"node-hk"} }, "path.recovered: Path no longer checked: mon-dd on cd-hs-sh"},
		{"disabled", func(m *model.Monitor) { m.Enabled = false }, "path.recovered: Path paused: mon-dd on cd-hs-sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := slowFixture(t, t.TempDir(), "mon-dd")
			f.operatorCheck("mon-dd", model.MonitorAlertDownAndDegraded, nil, "node-sh")
			pair := pathPair("mon-dd")
			f.evaluate()
			f.tick(runsFor(okRun(100), pair))
			expectNotices(t, "open", f.sweep(), "path.degraded: Path degraded: mon-dd on cd-hs-sh")
			mon, _ := f.st.Monitor("mon-dd")
			tc.change(&mon)
			if err := f.st.UpsertMonitor(mon); err != nil {
				t.Fatal(err)
			}
			got := f.sweep()
			expectNotices(t, tc.name, got, tc.title)
			if strings.Contains(got[0].title, "Path recovered") {
				t.Fatalf("closed as a recovery: %+v", got[0])
			}
			// Nothing reopens it while the change holds.
			f.clock.advance(time.Minute)
			f.evaluate()
			expectNotices(t, tc.name+", next evaluation", f.sweep())
		})
	}
	// A record the evaluator drops for another reason, here the source no
	// longer running the kind, closes with the path's unknown reason, so no
	// incident outlives its record.
	f := slowFixture(t, t.TempDir(), "mon-icmp")
	n, _ := f.st.Node("node-sh")
	n.ProbeMethods = []string{model.MonitorTypeTCP, model.MonitorTypeHTTP, model.MonitorTypeICMP}
	if err := f.st.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
	if err := f.st.UpsertMonitor(model.Monitor{ID: "mon-icmp", Name: "mon-icmp", Type: model.MonitorTypeICMP, Target: "203.0.113.3", Packets: 5,
		IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-sh"}, Enabled: true, Alert: model.MonitorAlertDownAndDegraded}); err != nil {
		t.Fatal(err)
	}
	pair := pathPair("mon-icmp")
	f.evaluate()
	f.tick(runsFor(model.MonitorResult{Success: true, LatencyMs: 100, Sent: 5, RTTsMs: []float64{100, 100, 100, 100, 100}}, pair))
	expectNotices(t, "icmp open", f.sweep(), "path.degraded: Path degraded: mon-icmp on cd-hs-sh")
	n.ProbeMethods = []string{model.MonitorTypeTCP, model.MonitorTypeHTTP}
	n.ProbeRefusals = map[string]string{model.MonitorTypeICMP: model.PathReasonICMPNotPermitted}
	if err := f.st.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Minute)
	if pass := f.evaluate(); pass.dropped != 1 || pass.judged != 0 {
		t.Fatalf("after the refusal: %+v", pass)
	}
	got := f.sweep()
	expectNotices(t, "dropped", got, "path.recovered: Path no longer judged: mon-icmp on cd-hs-sh")
	if !strings.Contains(got[0].body, "icmp_not_permitted") {
		t.Fatalf("dropped body = %q", got[0].body)
	}
	if recs, _ := f.st.PathDegradedRecords(); len(recs) != 0 {
		t.Fatalf("records after the drop = %+v", recs)
	}
}

// The path set's policy decides for its generated paths: off by default
// (nothing pages, as before M3), down pages monitor.down after alert_after
// failures, down_and_degraded adds path.degraded.
func TestPathSetAlertPolicy(t *testing.T) {
	gen := latencyMonitorID("node-jp")
	pair := pathPair(gen)
	t.Run("default off", func(t *testing.T) {
		f := slowFixture(t, t.TempDir(), gen)
		f.pathSet(model.LatencyProbeConfig{})
		f.evaluate()
		f.tick(runsFor(okRun(100), pair))
		if c := pathCellTo(t, f.matrix(), "node-sh", "node-jp"); c.State != model.PathStateDegraded {
			t.Fatalf("generated path = %+v", c)
		}
		f.tick(runsFor(failedRun, pair))
		f.tick(runsFor(failedRun, pair))
		f.tick(runsFor(failedRun, pair))
		if c := pathCellTo(t, f.matrix(), "node-sh", "node-jp"); c.State != model.PathStateDown {
			t.Fatalf("generated path after three failures = %+v", c)
		}
		expectNotices(t, "the default path set", f.sweep())
	})
	t.Run("down after alert_after", func(t *testing.T) {
		f := slowFixture(t, t.TempDir(), gen)
		f.pathSet(model.LatencyProbeConfig{Alert: model.MonitorAlertDown, AlertAfter: 3})
		f.evaluate()
		f.tick(runsFor(okRun(100), pair))
		f.tick(runsFor(failedRun, pair))
		f.tick(runsFor(failedRun, pair))
		if c := pathCellTo(t, f.matrix(), "node-sh", "node-jp"); c.State == model.PathStateDown {
			t.Fatalf("down after two failures with alert_after 3: %+v", c)
		}
		expectNotices(t, "two failures", f.sweep())
		f.tick(runsFor(failedRun, pair))
		if c := pathCellTo(t, f.matrix(), "node-sh", "node-jp"); c.State != model.PathStateDown {
			t.Fatalf("after three failures: %+v", c)
		}
		expectNotices(t, "three failures", f.sweep(), "monitor.down: Monitor down: Latency to tyo-3 on cd-hs-sh")
		f.tick(runsFor(okRun(100), pair))
		expectNotices(t, "back up", f.sweep(), "monitor.recovered: Monitor recovered: Latency to tyo-3 on cd-hs-sh")
	})
	t.Run("down and degraded", func(t *testing.T) {
		f := slowFixture(t, t.TempDir(), gen)
		f.pathSet(model.LatencyProbeConfig{Alert: model.MonitorAlertDownAndDegraded})
		f.evaluate()
		pending := f.srv.pendingIncidents(f.now())
		if len(pending) != 1 || pending[0].Kind != EventPathDegraded || pending[0].Key != pathDegradedKey(pair) ||
			!pending[0].UpdatedAt.Equal(degradedBase.Add(time.Minute)) || pending[0].Subject != "cd-hs-sh to tyo-3" {
			t.Fatalf("pending = %+v", pending)
		}
		f.tick(runsFor(okRun(100), pair))
		expectNotices(t, "entered", f.sweep(), "path.degraded: Path degraded: cd-hs-sh to tyo-3")
		if pending := f.srv.pendingIncidents(f.now()); len(pending) != 0 {
			t.Fatalf("pending once open = %+v", pending)
		}
		// Turned off mid-episode: the sweep closes it.
		f.pathSet(model.LatencyProbeConfig{Alert: model.MonitorAlertOff})
		expectNotices(t, "turned off", f.sweep(), "path.recovered: Degraded alerts off for cd-hs-sh to tyo-3")
		// Turned on again mid-episode: the next evaluation opens it.
		f.pathSet(model.LatencyProbeConfig{Alert: model.MonitorAlertDownAndDegraded})
		f.tick(runsFor(okRun(100), pair))
		expectNotices(t, "turned on again", f.sweep(), "path.degraded: Path degraded: cd-hs-sh to tyo-3")
	})
}

// A degraded record and a clearing one written by one server are read by the
// next on the same files: since and clear_since survive, the clearing path
// leaves ten minutes after its stored clear_since, and the new server opens
// no second incident and sends nothing.
func TestPathDegradedSurvivesARestartWithoutRealerting(t *testing.T) {
	dir := t.TempDir()
	f := slowFixture(t, dir, "mon-dd", "mon-clear")
	f.operatorCheck("mon-dd", model.MonitorAlertDownAndDegraded, nil, "node-sh")
	f.operatorCheck("mon-clear", model.MonitorAlertDownAndDegraded, nil, "node-sh")
	dd, clr := pathPair("mon-dd"), pathPair("mon-clear")
	f.evaluate()
	f.tick(map[store.MonitorPair]model.MonitorResult{dd: okRun(100), clr: okRun(100)})
	expectNotices(t, "before the restart", f.sweep(),
		"path.degraded: 2 paths degraded")
	var clearAt time.Time
	for i := 0; i < 20 && clearAt.IsZero(); i++ {
		if pass := f.tick(map[store.MonitorPair]model.MonitorResult{dd: okRun(100), clr: okRun(40)}); pass.cleared == 1 {
			clearAt = f.now()
		}
	}
	if clearAt.IsZero() {
		t.Fatal("mon-clear never started clearing")
	}
	f.clock.advance(3 * time.Minute)
	incDD, _ := f.st.ActiveIncident(pathDegradedKey(dd))
	at := f.now()
	f.close()

	g := openDegradedFixture(t, dir, nil)
	g.clock.at = at
	m := g.matrix()
	if m.DegradedAt != nil {
		t.Fatalf("degraded_at before the new server's first run = %v", m.DegradedAt)
	}
	cDD, cClr := pathCellFor(t, m, "node-sh", "mon-dd"), pathCellFor(t, m, "node-sh", "mon-clear")
	if cDD.State != model.PathStateDegraded || !cDD.Degraded.Since.Equal(degradedBase) || cDD.Degraded.ClearingSince != nil {
		t.Fatalf("degraded path after the restart = %+v", cDD.Degraded)
	}
	if cClr.State != model.PathStateDegraded || cClr.Degraded.ClearingSince == nil || !cClr.Degraded.ClearingSince.Equal(clearAt) {
		t.Fatalf("clearing path after the restart = %+v", cClr.Degraded)
	}
	left := time.Time{}
	for i := 0; i < 12 && left.IsZero(); i++ {
		if pass := g.tick(map[store.MonitorPair]model.MonitorResult{dd: okRun(100), clr: okRun(40)}); pass.left == 1 {
			left = g.now()
		}
	}
	if left.Sub(clearAt) != 10*time.Minute {
		t.Fatalf("left at %s, %s after clearing began, want ten minutes after the stored clear_since", left, left.Sub(clearAt))
	}
	got := g.sweep()
	for _, n := range got {
		if n.eventType == EventPathDegraded {
			t.Fatalf("the new server paged again: %+v", got)
		}
	}
	expectNotices(t, "after the restart", got, "path.recovered: Path recovered: mon-clear on cd-hs-sh")
	if again, ok := g.st.ActiveIncident(pathDegradedKey(dd)); !ok || again.ID != incDD.ID || again.Flaps != 0 {
		t.Fatalf("incident after the restart = %+v, before %s", again, incDD.ID)
	}
}
