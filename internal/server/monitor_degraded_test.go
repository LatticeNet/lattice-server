package server

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// degradedBase is the instant the degraded tests start judging at: fifty
// minutes into an hour, so the windows lie mostly inside the current hour
// and the baseline is the 168 whole hours before it.
var degradedBase = time.Date(2026, 10, 16, 12, 50, 0, 0, time.UTC)

// degradedFixture is a server on the production layout (state.json and
// state-hot.db) with a hand-moved clock, a source and a target node, and
// the typed notices the incident sweep sends recorded instead of routed.
type degradedFixture struct {
	t      *testing.T
	dir    string
	srv    *Server
	st     *store.Store
	clock  *testClock
	sent   *[]typedNotice
	closed bool
}

// writeHotHistory writes results straight into a hot store file before the
// store opens it, as the M1 benchmark seeds its fleet: the agent route
// refuses results more than a day old, and a week of baseline is the point.
func writeHotHistory(t testing.TB, path string, recs []store.MonitorResultRecord) {
	t.Helper()
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].At.Before(recs[j].At) })
	bs, err := store.OpenBoltState(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	// In batches: the golden fleet's 100 000 rows took 70 s under the race
	// detector in one bolt transaction and under 20 s in 5000s.
	for len(recs) > 0 {
		n := min(len(recs), 5000)
		if _, err := bs.RecordMonitorResults(recs[:n], store.DefaultMonitorHistoryLimits()); err != nil {
			t.Fatal(err)
		}
		recs = recs[n:]
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}
}

// baselineHistory is hours one-hour buckets of a pair before the hour of at,
// four successful runs each at ms.
func baselineHistory(monitorID, nodeID string, at time.Time, hours int, ms float64) []store.MonitorResultRecord {
	hour := at.UTC().Truncate(time.Hour)
	var out []store.MonitorResultRecord
	for h := 1; h <= hours; h++ {
		start := hour.Add(-time.Duration(h) * time.Hour)
		for _, m := range []int{3, 18, 33, 48} {
			ts := start.Add(time.Duration(m)*time.Minute + 7*time.Second)
			out = append(out, store.MonitorResultRecord{
				MonitorResult: model.MonitorResult{MonitorID: monitorID, NodeID: nodeID, At: ts, Success: true, LatencyMs: ms},
				ReceivedAt:    ts,
			})
		}
	}
	return out
}

// windowRuns is one run a minute over the hour up to at, the last at at; run
// gives each run's outcome, i counting from the oldest (0) to the newest
// (59).
func windowRuns(monitorID, nodeID string, at time.Time, run func(i int) (bool, float64)) []store.MonitorResultRecord {
	var out []store.MonitorResultRecord
	for i := 0; i < 60; i++ {
		ts := at.Add(-time.Duration(59-i) * time.Minute)
		ok, ms := run(i)
		out = append(out, store.MonitorResultRecord{
			MonitorResult: model.MonitorResult{MonitorID: monitorID, NodeID: nodeID, At: ts, Success: ok, LatencyMs: ms},
			ReceivedAt:    ts,
		})
	}
	return out
}

func slowRuns(int) (bool, float64) { return true, 100 }

func fastRuns(int) (bool, float64) { return true, 40 }

// lossyRuns lose five of the first fifty runs and none of the last ten.
func lossyRuns(i int) (bool, float64) { return !(i < 50 && i%10 == 0), 40 }

func openDegradedFixture(t *testing.T, dir string, history []store.MonitorResultRecord) *degradedFixture {
	t.Helper()
	hot := filepath.Join(dir, "state-hot.db")
	if history != nil {
		writeHotHistory(t, hot, history)
	}
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(hot); err != nil {
		t.Fatal(err)
	}
	srv, err := newClockedServer(t, Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	f := &degradedFixture{t: t, dir: dir, srv: srv, st: st, clock: serverClock(t, srv)}
	f.clock.set(degradedBase)
	f.sent = captureTypedNotices(srv)
	t.Cleanup(f.close)
	for _, n := range []model.Node{
		{ID: "node-sh", Name: "cd-hs-sh", Online: true, PublicIP: "203.0.113.1", Geo: &model.NodeGeo{Country: "CN"}},
		{ID: "node-hk", Name: "hk-edge", Online: true, PublicIP: "203.0.113.2", Geo: &model.NodeGeo{Country: "HK"}},
		{ID: "node-jp", Name: "tyo-3", Online: true, PublicIP: "203.0.113.3", Geo: &model.NodeGeo{Country: "JP"}},
	} {
		if _, ok := st.Node(n.ID); ok {
			continue
		}
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// operatorCheck stores a tcp check from sources to tyo-3's address.
func (f *degradedFixture) operatorCheck(id, alert string, rule *model.MonitorDegradedRule, sources ...string) {
	f.t.Helper()
	if err := f.st.UpsertMonitor(model.Monitor{ID: id, Name: id, Type: model.MonitorTypeTCP, Target: "203.0.113.3:443", IntervalSec: 60, TimeoutSec: 5,
		NodeIDs: sources, Enabled: true, Alert: alert, Degraded: rule, Version: 1}); err != nil {
		f.t.Fatal(err)
	}
}

// close shuts the server and the store, once.
func (f *degradedFixture) close() {
	if f.closed {
		return
	}
	f.closed = true
	f.srv.Close(context.Background())
	f.st.Close()
}

func (f *degradedFixture) now() time.Time { return f.clock.now() }

func (f *degradedFixture) evaluate() pathDegradedPass {
	return f.srv.evaluatePathDegraded(f.now())
}

func (f *degradedFixture) matrix() model.PathMatrix {
	f.t.Helper()
	m, err := f.srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return m
}

// tick moves the clock a minute, reports one run per pair through the agent
// route (so the alert hold runs) and evaluates.
func (f *degradedFixture) tick(runs map[store.MonitorPair]model.MonitorResult) pathDegradedPass {
	f.t.Helper()
	f.clock.advance(time.Minute)
	bySource := map[string][]model.MonitorResult{}
	for pair, r := range runs {
		r.MonitorID, r.At = pair.MonitorID, f.now()
		bySource[pair.NodeID] = append(bySource[pair.NodeID], r)
	}
	for source, results := range bySource {
		if _, err := f.srv.ingestAgentMonitorResults(source, results); err != nil {
			f.t.Fatal(err)
		}
	}
	return f.evaluate()
}

// sweep runs the incident pass and returns what it sent.
func (f *degradedFixture) sweep() []typedNotice {
	f.srv.evaluateIncidents(f.now())
	out := *f.sent
	*f.sent = nil
	return out
}

func okRun(ms float64) model.MonitorResult { return model.MonitorResult{Success: true, LatencyMs: ms} }

var failedRun = model.MonitorResult{Success: false, Error: "dial tcp: i/o timeout"}

// A path enters degraded on the second evaluation that finds the condition,
// shows its reason and evidence in the matrix, keeps counting down while
// clearing and leaves ten minutes after the condition went; degraded_at is
// null until the evaluator first runs.
func TestPathDegradedEntersShowsAndLeaves(t *testing.T) {
	var history []store.MonitorResultRecord
	history = append(history, baselineHistory("mon-op", "node-sh", degradedBase, 168, 40)...)
	history = append(history, windowRuns("mon-op", "node-sh", degradedBase, slowRuns)...)
	f := openDegradedFixture(t, t.TempDir(), history)
	f.operatorCheck("mon-op", "", nil, "node-sh")
	pair := store.MonitorPair{MonitorID: "mon-op", NodeID: "node-sh"}

	m := f.matrix()
	if m.DegradedAt != nil {
		t.Fatalf("degraded_at before the first run = %v", m.DegradedAt)
	}
	if c := pathCellFor(t, m, "node-sh", "mon-op"); c.State != model.PathStateUp || c.Degraded != nil {
		t.Fatalf("before any evaluation: %+v", c)
	}
	if pass := f.evaluate(); pass.judged != 1 || pass.entered != 0 {
		t.Fatalf("first evaluation = %+v", pass)
	}
	m = f.matrix()
	if m.DegradedAt == nil || !m.DegradedAt.Equal(degradedBase) {
		t.Fatalf("degraded_at after the first run = %v", m.DegradedAt)
	}
	if c := pathCellFor(t, m, "node-sh", "mon-op"); c.State != model.PathStateUp {
		t.Fatalf("one finding is pending, not degraded: %+v", c)
	}
	if pass := f.tick(map[store.MonitorPair]model.MonitorResult{pair: okRun(100)}); pass.entered != 1 {
		t.Fatalf("second evaluation = %+v", pass)
	}
	c := pathCellFor(t, f.matrix(), "node-sh", "mon-op")
	if c.State != model.PathStateDegraded || c.Reason != model.PathReasonDegradedLatency || c.Degraded == nil {
		t.Fatalf("after two findings: %+v", c)
	}
	d := c.Degraded
	if !d.Since.Equal(degradedBase) || !d.EvaluatedAt.Equal(degradedBase.Add(time.Minute)) || d.ClearingSince != nil || d.Loss != nil ||
		d.Latency == nil || d.Latency.P50Ms != 100 || d.Latency.BaselineMs != 40 || d.Latency.TriggerMs != 80 || d.Latency.Runs < 5 {
		t.Fatalf("degradation = %+v latency %+v", d, d.Latency)
	}
	recs, err := f.st.PathDegradedRecords()
	if err != nil || len(recs) != 1 || !recs[pair].EnteredAt.Equal(degradedBase.Add(time.Minute)) {
		t.Fatalf("stored records = %+v, %v", recs, err)
	}
	// Fast runs pull the 15-minute median back under the trigger: the path
	// starts clearing, still reads degraded, and leaves ten minutes later.
	var clearAt time.Time
	for i := 0; i < 30 && clearAt.IsZero(); i++ {
		if pass := f.tick(map[store.MonitorPair]model.MonitorResult{pair: okRun(40)}); pass.cleared == 1 {
			clearAt = f.now()
		}
	}
	if clearAt.IsZero() {
		t.Fatal("the path never started clearing")
	}
	c = pathCellFor(t, f.matrix(), "node-sh", "mon-op")
	if c.State != model.PathStateDegraded || c.Degraded.ClearingSince == nil || !c.Degraded.ClearingSince.Equal(clearAt) {
		t.Fatalf("clearing: %+v", c.Degraded)
	}
	for f.now().Sub(clearAt) < 9*time.Minute {
		if pass := f.tick(map[store.MonitorPair]model.MonitorResult{pair: okRun(40)}); pass.left != 0 {
			t.Fatalf("left %s after clearing began", f.now().Sub(clearAt))
		}
	}
	if pass := f.tick(map[store.MonitorPair]model.MonitorResult{pair: okRun(40)}); pass.left != 1 {
		t.Fatalf("ten minutes after clearing began: %+v", pass)
	}
	if c := pathCellFor(t, f.matrix(), "node-sh", "mon-op"); c.State != model.PathStateUp || c.Degraded != nil || c.Reason != "" {
		t.Fatalf("after leaving: %+v", c)
	}
	if recs, _ := f.st.PathDegradedRecords(); len(recs) != 0 {
		t.Fatalf("records after leaving: %+v", recs)
	}
}

// The gate and the floors against the store: 23 hours of baseline are never
// judged and 24 are; a lossy hour pages the loss arm; a check's own
// thresholds and the path set's for generated checks apply over the defaults;
// a tls check and a paused source are never judged.
func TestPathDegradedGateThresholdsAndScope(t *testing.T) {
	var history []store.MonitorResultRecord
	for _, c := range []struct {
		id    string
		hours int
		run   func(int) (bool, float64)
	}{
		{"mon-23", 23, slowRuns}, {"mon-24", 24, slowRuns}, {"mon-loss", 168, lossyRuns},
		{"mon-margin", 168, slowRuns}, {"mon-paused", 168, slowRuns}, {latencyMonitorID("node-jp"), 168, slowRuns},
	} {
		history = append(history, baselineHistory(c.id, "node-sh", degradedBase, c.hours, 40)...)
		history = append(history, windowRuns(c.id, "node-sh", degradedBase, c.run)...)
	}
	history = append(history, baselineHistory("mon-tls", "", degradedBase, 168, 40)...)
	history = append(history, windowRuns("mon-tls", "", degradedBase, slowRuns)...)
	f := openDegradedFixture(t, t.TempDir(), history)
	f.operatorCheck("mon-23", "", nil, "node-sh")
	f.operatorCheck("mon-24", "", nil, "node-sh")
	f.operatorCheck("mon-loss", "", nil, "node-sh")
	f.operatorCheck("mon-margin", "", &model.MonitorDegradedRule{LatencyMarginMs: 100}, "node-sh")
	f.operatorCheck("mon-paused", "", nil, "node-sh")
	paused, _ := f.st.Monitor("mon-paused")
	paused.PausedNodeIDs = []string{"node-sh"}
	if err := f.st.UpsertMonitor(paused); err != nil {
		t.Fatal(err)
	}
	if err := f.st.UpsertMonitor(model.Monitor{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "example.net:443", IntervalSec: 60, TimeoutSec: 5, ThresholdDays: 14, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	f.pathSet(model.LatencyProbeConfig{Degraded: &model.MonitorDegradedRule{LatencyFactor: 3}})

	f.evaluate()
	pass := f.evaluate()
	// mon-23, mon-24, mon-loss, mon-margin and the generated path; not the
	// paused source, not tls.
	if pass.judged != 5 {
		t.Fatalf("judged %d pairs, want 5", pass.judged)
	}
	m := f.matrix()
	for id, want := range map[string]string{
		"mon-23": model.PathStateUp, "mon-24": model.PathStateDegraded, "mon-loss": model.PathStateDegraded,
		"mon-margin": model.PathStateUp, "mon-paused": model.PathStateUnknown,
	} {
		if c := pathCellFor(t, m, "node-sh", id); c.State != want {
			t.Errorf("%s = %s (%s), want %s", id, c.State, c.Reason, want)
		}
	}
	if c := pathCellFor(t, m, "node-sh", "mon-loss"); c.Reason != model.PathReasonDegradedLoss || c.Degraded.Loss == nil ||
		c.Degraded.Loss.Sent < 30 || c.Degraded.Loss.Lost != 5 || c.Degraded.Loss.Trigger != 0.02 || c.Degraded.Latency != nil {
		t.Fatalf("loss path = %+v", c.Degraded)
	}
	// A tls check holds a week at 40 ms and an hour at 100 ms, which would
	// enter on latency, and is never judged.
	if c := pathCellFor(t, m, "", "mon-tls"); c.State != model.PathStateUp || c.Degraded != nil || c.Reason != "" {
		t.Fatalf("tls path = %+v", c)
	}
	recs, err := f.st.PathDegradedRecords()
	if err != nil {
		t.Fatal(err)
	}
	if _, held := recs[store.MonitorPair{MonitorID: "mon-tls"}]; held || len(recs) != 2 {
		t.Fatalf("records = %+v, want mon-24 and mon-loss only", recs)
	}
	// The path set's latency factor 3 puts the trigger at 120 ms.
	if c := pathCellTo(t, m, "node-sh", "node-jp"); c.State != model.PathStateUp || !c.Managed {
		t.Fatalf("generated path under the path set's rule = %+v", c)
	}
	f.pathSet(model.LatencyProbeConfig{})
	f.evaluate()
	f.evaluate()
	if c := pathCellTo(t, f.matrix(), "node-sh", "node-jp"); c.State != model.PathStateDegraded || c.Degraded.Latency.TriggerMs != 80 {
		t.Fatalf("generated path under the default rule = %+v", c)
	}
}

// pathDegradedEligible judges a path whose check can have results, and
// never a tls check, whatever else holds: the term must not rest on a tls
// path's empty source alone.
func TestPathDegradedEligibleNeverJudgesTLS(t *testing.T) {
	tcp := model.Monitor{ID: "mon-tcp", Type: model.MonitorTypeTCP, Enabled: true}
	tls := model.Monitor{ID: "mon-tls", Type: model.MonitorTypeTLS, Enabled: true}
	disabled := tcp
	disabled.Enabled = false
	entry := func(mon *model.Monitor, source string) pathEntry {
		return pathEntry{cell: model.PathCell{Source: source, MonitorID: mon.ID}, monitor: mon, hasCheck: true}
	}
	for name, tc := range map[string]struct {
		e    pathEntry
		want bool
	}{
		"tcp":                {entry(&tcp, "node-sh"), true},
		"tls from a source":  {entry(&tls, "node-sh"), false},
		"tls from the plane": {entry(&tls, ""), false},
		"no source":          {entry(&tcp, ""), false},
		"disabled":           {entry(&disabled, "node-sh"), false},
		"no check":           {pathEntry{cell: model.PathCell{Source: "node-sh"}}, false},
		"paused":             {func() pathEntry { e := entry(&tcp, "node-sh"); e.paused = true; return e }(), false},
		"gated":              {func() pathEntry { e := entry(&tcp, "node-sh"); e.gate = model.PathReasonAgentTooOld; return e }(), false},
		"not probeable":      {func() pathEntry { e := entry(&tcp, "node-sh"); e.notProbeable = true; return e }(), false},
	} {
		if got := pathDegradedEligible(tc.e); got != tc.want {
			t.Errorf("%s: eligible = %v, want %v", name, got, tc.want)
		}
	}
}

// failingRecords passes the evaluator's record writes to the store, or
// fails them while fail is set, counting every attempt.
type failingRecords struct {
	st         *store.Store
	fail       bool
	puts, dels int
}

func (r *failingRecords) PutPathDegradedRecord(pair store.MonitorPair, rec store.PathDegradedRecord) error {
	r.puts++
	if r.fail {
		return errors.New("write monitor_path_degraded: input/output error")
	}
	return r.st.PutPathDegradedRecord(pair, rec)
}

func (r *failingRecords) DeletePathDegradedRecord(pair store.MonitorPair) error {
	r.dels++
	if r.fail {
		return errors.New("write monitor_path_degraded: input/output error")
	}
	return r.st.DeletePathDegradedRecord(pair)
}

// failRecords routes the evaluator's writes through a failingRecords.
func (f *degradedFixture) failRecords() *failingRecords {
	r := &failingRecords{st: f.st}
	d := &f.srv.pathDegraded
	d.evalMu.Lock()
	d.records = r
	d.evalMu.Unlock()
	return r
}

// stored is pair's stored record.
func (f *degradedFixture) stored(pair store.MonitorPair) (store.PathDegradedRecord, bool) {
	f.t.Helper()
	recs, err := f.st.PathDegradedRecords()
	if err != nil {
		f.t.Fatal(err)
	}
	rec, ok := recs[pair]
	return rec, ok
}

// A transition the store refuses is not made in memory either: the matrix,
// the incident and the store keep reading the state before it, and the next
// evaluation makes it again. Entering, starting to clear, leaving and a drop
// each fail once and then go through.
func TestPathDegradedFailedWritesKeepMemoryAsStored(t *testing.T) {
	f := slowFixture(t, t.TempDir(), "mon-dd")
	f.operatorCheck("mon-dd", model.MonitorAlertDownAndDegraded, nil, "node-sh")
	pair := pathPair("mon-dd")
	key := pathDegradedKey(pair)
	recs := f.failRecords()
	cell := func() model.PathCell { return pathCellFor(t, f.matrix(), "node-sh", "mon-dd") }
	slow, fast := runsFor(okRun(100), pair), runsFor(okRun(40), pair)

	f.evaluate()
	recs.fail = true
	if pass := f.tick(slow); pass.failed != 1 || pass.entered != 0 || recs.puts != 1 {
		t.Fatalf("a refused enter = %+v, %d puts", pass, recs.puts)
	}
	if c := cell(); c.State != model.PathStateUp || c.Degraded != nil {
		t.Fatalf("after a refused enter: %+v", c)
	}
	if _, held := f.stored(pair); held {
		t.Fatal("a refused enter left a record")
	}
	if _, open := f.st.ActiveIncident(key); open {
		t.Fatal("a refused enter opened path.degraded")
	}
	if pending := f.srv.pendingIncidents(f.now()); len(pending) != 1 || pending[0].Key != key {
		t.Fatalf("pending after a refused enter = %+v", pending)
	}
	recs.fail = false
	if pass := f.tick(slow); pass.entered != 1 || pass.failed != 0 {
		t.Fatalf("the retried enter = %+v", pass)
	}
	rec, held := f.stored(pair)
	if !held || !rec.Since.Equal(degradedBase) || !rec.EnteredAt.Equal(f.now()) {
		t.Fatalf("stored after the retried enter = %+v", rec)
	}
	if c := cell(); c.State != model.PathStateDegraded || !c.Degraded.Since.Equal(degradedBase) {
		t.Fatalf("after the retried enter: %+v", c.Degraded)
	}
	if _, open := f.st.ActiveIncident(key); !open {
		t.Fatal("the retried enter opened nothing")
	}

	// Starting to clear is refused: both still read degraded, not clearing.
	recs.fail = true
	puts := recs.puts
	for i := 0; i < 30 && recs.puts == puts; i++ {
		f.tick(fast)
	}
	if recs.puts == puts {
		t.Fatal("the path never tried to start clearing")
	}
	absentAt := f.now()
	if c := cell(); c.State != model.PathStateDegraded || c.Degraded.ClearingSince != nil {
		t.Fatalf("after a refused start of clearing: %+v", c.Degraded)
	}
	if rec, _ := f.stored(pair); rec.Clearing() {
		t.Fatalf("stored after a refused start of clearing = %+v", rec)
	}
	recs.fail = false
	if pass := f.tick(fast); pass.cleared != 1 || pass.failed != 0 {
		t.Fatalf("the retried start of clearing = %+v", pass)
	}
	clearAt := f.now()
	if !clearAt.Equal(absentAt.Add(time.Minute)) {
		t.Fatalf("clearing began at %s, the refused try at %s", clearAt, absentAt)
	}
	if rec, _ := f.stored(pair); !rec.ClearSince.Equal(clearAt) {
		t.Fatalf("stored clear_since = %s, want %s", rec.ClearSince, clearAt)
	}
	if c := cell(); c.Degraded.ClearingSince == nil || !c.Degraded.ClearingSince.Equal(clearAt) {
		t.Fatalf("matrix clearing since = %+v", c.Degraded)
	}

	// Leaving is refused: the record stays in both, the incident stays
	// open and owes nothing yet.
	recs.fail = true
	var pass pathDegradedPass
	for f.now().Sub(clearAt) < model.PathDegradedLeaveAfter {
		pass = f.tick(fast)
	}
	if pass.failed != 1 || pass.left != 0 || recs.dels != 1 {
		t.Fatalf("a refused leave = %+v, %d deletes", pass, recs.dels)
	}
	if _, held := f.stored(pair); !held {
		t.Fatal("a refused leave lost the record")
	}
	if c := cell(); c.State != model.PathStateDegraded || c.Degraded.ClearingSince == nil {
		t.Fatalf("after a refused leave: %+v", c)
	}
	if _, open := f.st.ActiveIncident(key); !open {
		t.Fatal("a refused leave resolved the incident")
	}
	recs.fail = false
	if pass := f.tick(fast); pass.left != 1 || pass.failed != 0 {
		t.Fatalf("the retried leave = %+v", pass)
	}
	if _, held := f.stored(pair); held {
		t.Fatal("the retried leave kept the record")
	}
	if _, open := f.st.ActiveIncident(key); open {
		t.Fatal("the retried leave left the incident open")
	}

	// A drop the store refuses keeps the entry, and the next evaluation
	// drops it.
	for i := 0; i < 20; i++ {
		if _, held := f.stored(pair); held {
			break
		}
		f.tick(slow)
	}
	if _, held := f.stored(pair); !held {
		t.Fatal("slow again, the path did not enter")
	}
	mon, _ := f.st.Monitor("mon-dd")
	mon.PausedNodeIDs = []string{"node-sh"}
	if err := f.st.UpsertMonitor(mon); err != nil {
		t.Fatal(err)
	}
	recs.fail = true
	f.clock.advance(time.Minute)
	if pass := f.evaluate(); pass.failed != 1 || pass.dropped != 0 {
		t.Fatalf("a refused drop = %+v", pass)
	}
	if _, held := f.stored(pair); !held {
		t.Fatal("a refused drop lost the record")
	}
	if _, kept := f.srv.pathDegradedSnapshot().entries[pair]; !kept {
		t.Fatal("a refused drop forgot the entry")
	}
	recs.fail = false
	f.clock.advance(time.Minute)
	if pass := f.evaluate(); pass.dropped != 1 || pass.failed != 0 {
		t.Fatalf("the retried drop = %+v", pass)
	}
	if _, held := f.stored(pair); held {
		t.Fatal("the retried drop kept the record")
	}
	if _, kept := f.srv.pathDegradedSnapshot().entries[pair]; kept {
		t.Fatal("the retried drop kept the entry")
	}
}

// pathSet stores the path set cfg names (sources node-sh, auto targets,
// tcp), with tyo-3's generated check in place, and plans it.
func (f *degradedFixture) pathSet(cfg model.LatencyProbeConfig) {
	f.t.Helper()
	cfg.Enabled, cfg.IntervalSec, cfg.TimeoutSec, cfg.AutoTargets = true, 60, 5, true
	if cfg.Sources == nil {
		cfg.Sources = []string{"node-sh"}
	}
	id := latencyMonitorID("node-jp")
	if _, ok := f.st.Monitor(id); !ok {
		if err := f.st.UpsertMonitor(model.Monitor{ID: id, Name: "Latency to tyo-3", Type: model.MonitorTypeTCP, Target: "203.0.113.3:443", TargetNode: "node-jp",
			IntervalSec: 60, TimeoutSec: 5, NodeIDs: cfg.Sources, Enabled: true, ManagedBy: model.MonitorManagedLatency}); err != nil {
			f.t.Fatal(err)
		}
	}
	prior, _ := f.st.LatencyProbeConfig()
	if _, err := f.st.SetLatencyProbeConfig(cfg, prior.Version, "admin", f.now()); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err := f.srv.syncLatencyProbes(f.now()); err != nil {
		f.t.Fatal(err)
	}
	f.srv.monitorPaths.notePlan(f.srv.planLatencyProbes(f.now()), f.now())
}

// Down and unknown win over degraded in the matrix, and the record keeps
// running underneath: a path that comes back from an outage reads degraded
// again while the hour still holds its failures.
func TestPathDegradedDownAndUnknownWin(t *testing.T) {
	var history []store.MonitorResultRecord
	history = append(history, baselineHistory("mon-op", "node-sh", degradedBase, 168, 40)...)
	history = append(history, windowRuns("mon-op", "node-sh", degradedBase, lossyRuns)...)
	f := openDegradedFixture(t, t.TempDir(), history)
	f.operatorCheck("mon-op", "", nil, "node-sh")
	pair := store.MonitorPair{MonitorID: "mon-op", NodeID: "node-sh"}
	f.evaluate()
	f.tick(map[store.MonitorPair]model.MonitorResult{pair: okRun(40)})
	if c := pathCellFor(t, f.matrix(), "node-sh", "mon-op"); c.State != model.PathStateDegraded {
		t.Fatalf("lossy path = %+v", c)
	}
	f.tick(map[store.MonitorPair]model.MonitorResult{pair: failedRun})
	f.tick(map[store.MonitorPair]model.MonitorResult{pair: failedRun})
	if c := pathCellFor(t, f.matrix(), "node-sh", "mon-op"); c.State != model.PathStateDown || c.Degraded != nil || c.Reason != "" {
		t.Fatalf("down beside a degraded record = %+v", c)
	}
	f.tick(map[store.MonitorPair]model.MonitorResult{pair: okRun(40)})
	if c := pathCellFor(t, f.matrix(), "node-sh", "mon-op"); c.State != model.PathStateDegraded {
		t.Fatalf("back from the outage, the hour still holds its failures: %+v", c)
	}
	n, _ := f.st.Node("node-sh")
	n.Online = false
	if err := f.st.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
	if c := pathCellFor(t, f.matrix(), "node-sh", "mon-op"); c.State != model.PathStateUnknown || c.Reason != model.PathReasonAgentOffline {
		t.Fatalf("offline source beside a degraded record = %+v", c)
	}
}

// A method switch starts a new gate: the state is judged on the check the
// path uses now, which has no week of its own yet, and the old check's
// record is dropped.
func TestPathDegradedMethodSwitchStartsANewGate(t *testing.T) {
	tcp := latencyMonitorID("node-jp")
	var history []store.MonitorResultRecord
	history = append(history, baselineHistory(tcp, "node-sh", degradedBase, 168, 40)...)
	history = append(history, windowRuns(tcp, "node-sh", degradedBase, slowRuns)...)
	f := openDegradedFixture(t, t.TempDir(), history)
	f.pathSet(model.LatencyProbeConfig{})
	f.evaluate()
	f.evaluate()
	if c := pathCellTo(t, f.matrix(), "node-sh", "node-jp"); c.State != model.PathStateDegraded || c.MonitorID != tcp {
		t.Fatalf("tcp path = %+v", c)
	}
	// The source learns icmp and the path set picks it.
	n, _ := f.st.Node("node-sh")
	n.ProbeMethods = []string{model.MonitorTypeTCP, model.MonitorTypeHTTP, model.MonitorTypeICMP}
	if err := f.st.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
	f.pathSet(model.LatencyProbeConfig{Method: model.LatencyMethodICMP})
	icmp := latencyICMPMonitorID("node-jp")
	slow := map[store.MonitorPair]model.MonitorResult{{MonitorID: icmp, NodeID: "node-sh"}: {Success: true, LatencyMs: 100, Sent: 5, RTTsMs: []float64{100, 100, 100, 100, 100}}}
	for i := 0; i < 3; i++ {
		f.tick(slow)
	}
	c := pathCellTo(t, f.matrix(), "node-sh", "node-jp")
	if c.MonitorID != icmp || c.State != model.PathStateUp {
		t.Fatalf("after the switch the icmp check has no week yet: %+v", c)
	}
	recs, _ := f.st.PathDegradedRecords()
	if _, held := recs[store.MonitorPair{MonitorID: tcp, NodeID: "node-sh"}]; held || len(recs) != 0 {
		t.Fatalf("records after the switch = %+v", recs)
	}
}

// The evaluator, matrix and series reads, ingest and the incident sweep run
// at once; the race detector holds the snapshot and the baseline cache to
// account.
func TestPathDegradedRunsBesideReads(t *testing.T) {
	var history []store.MonitorResultRecord
	for _, id := range []string{"mon-a", "mon-b"} {
		history = append(history, baselineHistory(id, "node-sh", degradedBase, 168, 40)...)
		history = append(history, windowRuns(id, "node-sh", degradedBase, slowRuns)...)
	}
	f := openDegradedFixture(t, t.TempDir(), history)
	f.operatorCheck("mon-a", model.MonitorAlertDownAndDegraded, nil, "node-sh")
	f.operatorCheck("mon-b", "", nil, "node-sh")
	p := principal{Principal: adminPrincipalForTest()}
	done := make(chan error, 8)
	go func() {
		for i := 0; i < 20; i++ {
			f.srv.evaluatePathDegraded(degradedBase.Add(time.Duration(i) * time.Minute))
		}
		done <- nil
	}()
	for g := 0; g < 3; g++ {
		go func() {
			for i := 0; i < 20; i++ {
				at := degradedBase.Add(time.Duration(i) * time.Minute)
				if _, err := f.srv.pathMatrixFor(p, model.PathWindowHour, at); err != nil {
					done <- err
					return
				}
				if _, err := f.srv.pathBaselineView(store.MonitorPair{MonitorID: "mon-b", NodeID: "node-sh"}, model.MonitorDegradedRule{}, at); err != nil {
					done <- err
					return
				}
				f.srv.pendingIncidents(at)
			}
			done <- nil
		}()
	}
	go func() {
		for i := 0; i < 20; i++ {
			at := degradedBase.Add(time.Duration(i)*time.Minute + time.Second)
			if _, err := f.st.IngestAgentMonitorResults("node-sh", []model.MonitorResult{{MonitorID: "mon-a", At: at, Success: true, LatencyMs: 100}}, at); err != nil {
				done <- err
				return
			}
			f.srv.evaluateIncidents(at)
		}
		done <- nil
	}()
	for i := 0; i < 5; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
