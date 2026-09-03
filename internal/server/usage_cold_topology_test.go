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
	// Only the inbound family is held. Everything else advances, which is what
	// keeps named counters flowing and keeps restart detection honest.
	if after.CoreUptimeSec != 300 {
		t.Fatalf("baseline uptime = %d, want the held report's 300: only the inbound family is frozen", after.CoreUptimeSec)
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
	// Exhaust the hold window, then the report is recorded the way it is today.
	f.report(t, 300, 600, 600)
	f.advance(usageColdTopologyDeferMax + time.Minute)
	res := f.report(t, 400, 600, 600)
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

	if res := f.report(t, 300, 150, 150); !res.InboundDeferred {
		t.Fatalf("the first cold report should be held: %+v", res)
	}
	// A held report still advances the stored baseline's timestamp, so the bound
	// cannot be measured from it: a node that keeps reporting would refresh it
	// on every poll and hold forever. It is measured from when holding started.
	f.advance(usageColdTopologyDeferMax - time.Minute)
	if res := f.report(t, 400, 200, 200); !res.InboundDeferred {
		t.Fatalf("inside the bound the report should still be held: %+v", res)
	}
	f.advance(2 * time.Minute)
	res := f.report(t, 500, 300, 300)
	if res.InboundDeferred {
		t.Fatalf("past the bound the report must be recorded: %+v", res)
	}
	if res.UnknownLines != 1 {
		t.Fatalf("unknown lines = %d, want 1: past the bound the bytes are recorded, not dropped", res.UnknownLines)
	}
	// And once a report is recorded, the next hold starts a fresh window rather
	// than inheriting the exhausted one.
	f.goWarm(t)
	f.advance(time.Minute)
	f.report(t, 600, 400, 400)
	f.goCold(t)
	f.advance(time.Minute)
	if res := f.report(t, 700, 500, 500); !res.InboundDeferred {
		t.Fatalf("a fresh gap after a recorded report should be held: %+v", res)
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

	if !f.srv.deferUsageForColdTopology(ctx, snapshot, recent, true, false, *f.now) {
		t.Fatal("a report with a recent baseline and no topology should be held")
	}
	if f.srv.deferUsageForColdTopology(ctx, snapshot, recent, false, false, *f.now) {
		t.Fatal("a first report was held: with no baseline nothing is consumed, so " +
			"establishing one is right and holding would leave the next report " +
			"diffing against nothing")
	}
	empty := model.ProxyUsageSnapshot{NodeID: "node-a"}
	if f.srv.deferUsageForColdTopology(ctx, empty, recent, true, false, *f.now) {
		t.Fatal("a report carrying no inbound counters was held; there is nothing to lose")
	}
	if f.srv.deferUsageForColdTopology(ctx, snapshot, recent, true, true, *f.now) {
		t.Fatal("a report after a core restart was held: the current value is the delta, " +
			"and holding it stores a pre-restart baseline the next report diffs to nothing")
	}
	// The bound reads the hold's own start, not the baseline's age. A stale
	// baseline on a node that has never been held is still holdable: that is
	// exactly a node coming back after a long quiet period.
	stale := model.ProxyUsageSnapshot{NodeID: "node-a", At: f.now.Add(-24 * time.Hour)}
	if !f.srv.deferUsageForColdTopology(ctx, snapshot, stale, true, false, *f.now) {
		t.Fatal("a node that has not been held was refused on baseline age alone")
	}
	f.srv.usageInboundHeldSince = map[string]time.Time{
		"node-a": f.now.Add(-usageColdTopologyDeferMax - time.Second),
	}
	if f.srv.deferUsageForColdTopology(ctx, snapshot, recent, true, false, *f.now) {
		t.Fatal("a node held for longer than the bound was held again")
	}
	f.srv.usageInboundHeldSince = nil
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

// Only the inbound family is held. A named counter is proof on its own and is
// already attributed while discovery is stale, which this must not undo: that
// decision is what server_proxy.go's folded-counter comment records, and
// TestUsageNamedCounterSurvivesStaleDiscovery holds the line on it.
func TestUsageColdTopologyHoldsOnlyTheInboundFamily(t *testing.T) {
	f := newColdTopologyFixture(t)
	name := userLineName(f.fleet.alice.ID, f.fleet.hub.LineUUID)
	send := func(uptime uint64, inbound, named int64) proxyUsageApplyResult {
		return mustApplyUsage(t, f.srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: uptime,
			InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(inbound, inbound)},
			UserTraffic:    map[string]model.ProxyTrafficCounter{name: counter(named, named)}})
	}
	send(100, 10, 5)
	f.goCold(t)
	f.advance(time.Minute)
	res := send(200, 100, 50)
	if !res.InboundDeferred {
		t.Fatalf("the inbound family should be held: %+v", res)
	}
	if res.UsersUpdated != 1 {
		t.Fatalf("users updated = %d, want 1: the named counter is proof and must still be attributed", res.UsersUpdated)
	}
	day := store.UsageDay(*f.now)
	rows, _ := f.srv.store.UsageDayUserRows(f.fleet.alice.ID, day, day)
	total := int64(0)
	for _, row := range rows {
		total += row.Uplink + row.Downlink
	}
	if total != 90 {
		t.Fatalf("alice = %d, want 90 (the named delta of 45 each way)", total)
	}
	// The named baseline advanced with the report; only the inbound one did not.
	baseline := f.baseline(t)
	if got := baseline.UserTraffic[name]; got != counter(50, 50) {
		t.Fatalf("named baseline = %+v, want 50/50", got)
	}
	if got := baseline.InboundTraffic["hub-a"]; got != counter(10, 10) {
		t.Fatalf("inbound baseline = %+v, want the pre-gap 10/10", got)
	}
}
