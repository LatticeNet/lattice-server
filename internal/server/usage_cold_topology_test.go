package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A node's lines live in an in-memory discovery mirror that is evicted after
// nodeOfflineThreshold, so an agent that misses a couple of inventory posts
// reports real counters into an empty topology. Recorded, those counters become
// unknown_line rows with no identity: no UsageDayUser row is written, the
// cumulative delta is consumed anyway, and quota reads exactly the rows that
// were never written. The traffic is short forever while the per-line view
// re-derives the full number once discovery returns.
//
// This was watched in production: unknown_line went from 2 to 15 for about ten
// minutes on one node, covering rows carrying hundreds of megabytes, and healed
// on its own when the agent posted again. The visible half heals; the half that
// decides quota does not.

// coldTopologyFixture is one node with one line, one identity bound to it, and
// a clock the test drives.
type coldTopologyFixture struct {
	srv   *Server
	fleet usageFleet
	now   *time.Time
	saved map[string]model.SingBoxInventory
}

func newColdTopologyFixture(t *testing.T) *coldTopologyFixture {
	t.Helper()
	start := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := start
	srv := usageTestServer(t, start)
	srv.now = func() time.Time { return clock }
	f := &coldTopologyFixture{srv: srv, now: &clock}
	f.fleet = seedUsageFleet(t, srv)
	srv.singboxInvMu.RLock()
	f.saved = srv.singboxInv
	srv.singboxInvMu.RUnlock()
	return f
}

func (f *coldTopologyFixture) advance(d time.Duration) { *f.now = f.now.Add(d) }

// goCold drops the discovery mirror the way liveSingBoxInventories' eviction
// leaves it: the node exists, its profile exists, and it has no lines.
func (f *coldTopologyFixture) goCold(t *testing.T) {
	t.Helper()
	f.srv.singboxInvMu.Lock()
	f.srv.singboxInv = map[string]model.SingBoxInventory{}
	f.srv.singboxInvMu.Unlock()
	f.srv.invalidateLineReadModel()
	if got := len(f.srv.usageAttributionContext().byNodeTag["node-a"]); got != 0 {
		t.Fatalf("node-a still has %d lines in the read model; the fixture is not cold", got)
	}
}

// goWarm is the agent's next successful inventory post: the same lines, stamped
// now. Restoring them with their original timestamp would not warm anything,
// because liveSingBoxInventories evicts on age and would drop them again.
func (f *coldTopologyFixture) goWarm(t *testing.T) {
	t.Helper()
	f.srv.singboxInvMu.Lock()
	fresh := make(map[string]model.SingBoxInventory, len(f.saved))
	for id, inv := range f.saved {
		inv.At = *f.now
		fresh[id] = inv
	}
	f.srv.singboxInv = fresh
	f.srv.singboxInvMu.Unlock()
	f.srv.invalidateLineReadModel()
	if got := len(f.srv.usageAttributionContext().byNodeTag["node-a"]); got == 0 {
		t.Fatal("node-a still has no lines after the inventory came back")
	}
}

// report sends one cumulative counter for direct-a, the line bob is the only
// enabled binding on.
func (f *coldTopologyFixture) report(t *testing.T, uptime uint64, up, down int64) proxyUsageApplyResult {
	t.Helper()
	return mustApplyUsage(t, f.srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: uptime,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(up, down)}})
}

// bobBytes is what quota actually reads: the stored per-identity day rows.
func (f *coldTopologyFixture) bobBytes(t *testing.T) int64 {
	t.Helper()
	day := store.UsageDay(*f.now)
	rows, err := f.srv.store.UsageDayUserRows(f.fleet.bob.ID, day, day)
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	for _, row := range rows {
		total += row.Uplink + row.Downlink
	}
	return total
}

func (f *coldTopologyFixture) baseline(t *testing.T) model.ProxyUsageSnapshot {
	t.Helper()
	snap, ok := f.srv.store.ProxyUsageSnapshot("node-a")
	if !ok {
		t.Fatal("no stored baseline for node-a")
	}
	return snap
}

// The two guarantees: a report arriving with no line facts leaves the baseline
// where it was, so the delta is not consumed; and once discovery returns, the
// identity's total is what the node counted rather than what survived the gap.
func TestUsageIngestDefersWhileTopologyIsColdAndRecoversTheWholeGap(t *testing.T) {
	f := newColdTopologyFixture(t)
	f.report(t, 100, 0, 0) // baseline
	f.advance(time.Minute)
	f.report(t, 200, 100, 100) // one healthy delta: bob is credited 200
	if got := f.bobBytes(t); got != 200 {
		t.Fatalf("bob after the healthy delta = %d, want 200", got)
	}
	before := f.baseline(t)

	f.goCold(t)
	f.advance(time.Minute)
	res := f.report(t, 300, 600, 600)
	if !res.InboundDeferred {
		t.Fatalf("a report with no line facts was recorded rather than held: %+v", res)
	}
	if res.UnknownLines != 0 {
		t.Fatalf("a held report still produced %d unknown_line rows", res.UnknownLines)
	}

	// (1) Nothing was consumed. The stored baseline is byte-for-byte the one the
	// last attributable report left, so the next diff starts where it did.
	after := f.baseline(t)
	if got, want := after.InboundTraffic["direct-a"], before.InboundTraffic["direct-a"]; got != want {
		t.Fatalf("baseline advanced during the gap: %+v, want %+v", got, want)
	}
	if after.CoreUptimeSec != before.CoreUptimeSec {
		t.Fatalf("baseline uptime advanced during the gap: %d, want %d", after.CoreUptimeSec, before.CoreUptimeSec)
	}
	if got := f.bobBytes(t); got != 200 {
		t.Fatalf("bob moved during the gap: %d, want 200", got)
	}

	// (2) Discovery returns and the next report carries the whole gap.
	f.goWarm(t)
	f.advance(time.Minute)
	res = f.report(t, 400, 600, 600)
	if res.InboundDeferred {
		t.Fatalf("still holding after discovery returned: %+v", res)
	}
	if got := f.bobBytes(t); got != 1200 {
		t.Fatalf("bob after recovery = %d, want 1200: the node counted 1200 on that line, "+
			"and quota must see what the node counted, not what survived the gap", got)
	}
	if got := f.baseline(t).InboundTraffic["direct-a"]; got != counter(600, 600) {
		t.Fatalf("baseline after recovery = %+v, want 600/600", got)
	}
}

// Without the fix the same sequence loses the gap permanently, and the two
// surfaces disagree about the same line forever. This pins the shape of the
// defect so a future change cannot quietly reintroduce it.
func TestUsageColdTopologyLossIsWhatTheDeferralPrevents(t *testing.T) {
	f := newColdTopologyFixture(t)
	f.report(t, 100, 0, 0)
	f.advance(time.Minute)
	f.report(t, 200, 100, 100)

	f.goCold(t)
	// Past the bound, the report is recorded the way it is today.
	f.advance(usageColdTopologyDeferMax + time.Minute)
	res := f.report(t, 300, 600, 600)
	if res.InboundDeferred {
		t.Fatalf("held a report whose baseline is older than the bound: %+v", res)
	}
	if res.UnknownLines != 1 {
		t.Fatalf("unknown lines = %d, want 1", res.UnknownLines)
	}
	if res.UsersUpdated != 0 {
		t.Fatalf("users updated = %d, want 0: nothing can be attributed with no topology", res.UsersUpdated)
	}

	f.goWarm(t)
	// Quota is short by the whole gap, permanently: the delta was consumed and
	// no per-identity row was ever written for it.
	if got := f.bobBytes(t); got != 200 {
		t.Fatalf("bob = %d, want 200 (the loss this bound deliberately accepts)", got)
	}
	// And the per-line view re-derives the full number, so the two disagree.
	window, _ := parseUsagePeriod("today", *f.now)
	report, _ := f.srv.buildUsageLines(f.srv.usageAttributionContext(), window)
	for _, row := range report.Rows {
		if row.Tag == "direct-a" && row.UsedBytes != 1200 {
			t.Fatalf("per-line row = %d bytes, want 1200", row.UsedBytes)
		}
	}
}

// The bound exists so a node whose discovery never returns cannot stall its
// accounting silently and forever. Holding must stop being safe at some age,
// and the report must then be recorded rather than dropped.
func TestUsageColdTopologyDeferralIsBounded(t *testing.T) {
	f := newColdTopologyFixture(t)
	f.report(t, 100, 0, 0)
	f.advance(time.Minute)
	f.report(t, 200, 100, 100)
	f.goCold(t)

	f.advance(usageColdTopologyDeferMax - time.Minute)
	if res := f.report(t, 300, 200, 200); !res.InboundDeferred {
		t.Fatalf("inside the bound the report should be held: %+v", res)
	}
	// The held report did not advance At either, so the baseline keeps ageing
	// from the last recorded one and the bound cannot be extended indefinitely
	// by a node that keeps reporting.
	f.advance(2 * time.Minute)
	if res := f.report(t, 400, 300, 300); res.InboundDeferred {
		t.Fatalf("past the bound the report must be recorded: %+v", res)
	}
}

// A first report is never held: with no baseline nothing is consumed, so the
// honest move is to establish one. Holding instead would leave the next report
// diffing against nothing and counting the core's whole lifetime.
func TestUsageColdTopologyNeverDefersTheFirstReport(t *testing.T) {
	f := newColdTopologyFixture(t)
	f.goCold(t)
	res := f.report(t, 100, 500, 500)
	if res.InboundDeferred {
		t.Fatalf("the first report was held: %+v", res)
	}
	if got := f.baseline(t).InboundTraffic["direct-a"]; got != counter(500, 500) {
		t.Fatalf("first report did not establish a baseline: %+v", got)
	}
	if got := f.bobBytes(t); got != 0 {
		t.Fatalf("a first report counted %d bytes; it establishes a baseline only", got)
	}
}

// A tag with no line while the node's other lines resolve is a genuine unknown
// tag, not a cold read model, and must still be recorded as one.
func TestUsageColdTopologyDoesNotDeferAGenuineUnknownTag(t *testing.T) {
	f := newColdTopologyFixture(t)
	f.report(t, 100, 0, 0)
	f.advance(time.Minute)
	f.goWarm(t) // the agent keeps posting inventory; the node stays discovered
	res := mustApplyUsage(t, f.srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 200,
		InboundTraffic: map[string]model.ProxyTrafficCounter{
			"direct-a": counter(100, 100), "ghost": counter(7, 7),
		}})
	if res.InboundDeferred {
		t.Fatalf("held a report whose node has lines: %+v", res)
	}
	if res.UnknownLines != 1 {
		t.Fatalf("unknown lines = %d, want 1 for the ghost tag", res.UnknownLines)
	}

	// And the sharper case: a report in which NOTHING resolves, on a node whose
	// lines are all present. "No tag in this report resolved" and "this node has
	// no topology" look identical from the counters alone, and only the second
	// is safe to hold. Deciding on the report would hold a node that is fully
	// discovered and simply reporting tags that do not exist, and would keep
	// holding it forever because rediscovery cannot change the answer.
	f.advance(time.Minute)
	f.goWarm(t)
	res = mustApplyUsage(t, f.srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 300,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"ghost": counter(20, 20)}})
	if res.InboundDeferred {
		t.Fatalf("held a report on a fully discovered node because none of its tags resolved: %+v", res)
	}
	if res.UnknownLines != 1 {
		t.Fatalf("unknown lines = %d, want 1", res.UnknownLines)
	}
}

// The first-report guard, stated directly. It cannot be reached through the
// apply path, because a node with no baseline also has a zero-valued previous
// whose age is past any bound, so the bound masks it. That accident is exactly
// why the guard is worth pinning on its own: the two conditions must each hold
// alone, or a later change to the bound silently changes what happens to a
// node's very first report.
func TestDeferUsageForColdTopologyGuards(t *testing.T) {
	f := newColdTopologyFixture(t)
	f.goCold(t)
	ctx := f.srv.usageAttributionContext()
	snapshot := model.ProxyUsageSnapshot{NodeID: "node-a",
		InboundTraffic: map[string]model.ProxyTrafficCounter{"direct-a": counter(5, 5)}}
	recent := model.ProxyUsageSnapshot{NodeID: "node-a", At: f.now.Add(-time.Minute)}

	if !f.srv.deferUsageForColdTopology(ctx, snapshot, recent, true, *f.now) {
		t.Fatal("a report with a recent baseline and no topology should be held")
	}
	if f.srv.deferUsageForColdTopology(ctx, snapshot, recent, false, *f.now) {
		t.Fatal("a first report was held: with no baseline nothing is consumed, so " +
			"establishing one is right and holding would leave the next report " +
			"diffing against nothing")
	}
	empty := model.ProxyUsageSnapshot{NodeID: "node-a"}
	if f.srv.deferUsageForColdTopology(ctx, empty, recent, true, *f.now) {
		t.Fatal("a report carrying no inbound counters was held; there is nothing to lose")
	}
	stale := model.ProxyUsageSnapshot{NodeID: "node-a", At: f.now.Add(-usageColdTopologyDeferMax - time.Second)}
	if f.srv.deferUsageForColdTopology(ctx, snapshot, stale, true, *f.now) {
		t.Fatal("a report whose baseline is past the bound was held")
	}
}

// An operator reading the usage surface during a gap should be told the line is
// known and the node is not reporting topology, not that no line carries the
// tag. The second sends them looking for a config change that never happened.
func TestUsageReadNamesAKnownLineWithNoLiveTopology(t *testing.T) {
	f := newColdTopologyFixture(t)
	f.report(t, 100, 0, 0)
	f.advance(time.Minute)
	f.report(t, 200, 100, 100)
	wantHash := f.fleet.direct.LineHashID

	f.goCold(t)
	window, _ := parseUsagePeriod("today", *f.now)
	report, _ := f.srv.buildUsageLines(f.srv.usageAttributionContext(), window)
	found := false
	for _, row := range report.Rows {
		if row.Tag != "direct-a" {
			continue
		}
		found = true
		if row.Attribution != usageAttributionUnknownLine {
			t.Fatalf("direct-a row = %+v, want unknown_line while the topology is missing", row)
		}
		if row.LineHashID != wantHash {
			t.Fatalf("row line hash = %q, want %q: the server does know which line this is", row.LineHashID, wantHash)
		}
		if row.AttributionReason != "this tag's line is known but the node reports no live topology" {
			t.Fatalf("row reason = %q", row.AttributionReason)
		}
	}
	if !found {
		t.Fatal("no direct-a row in the report")
	}
}
