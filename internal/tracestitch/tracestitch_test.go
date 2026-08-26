package tracestitch

import (
	"reflect"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The rig from SINGBOX-TRACE-DESIGN section 4.5: an entry instance with a
// mixed inbound chained to an exit instance, both logging the final
// destination.
const (
	entryNode   = "node-entry"
	exitNode    = "node-exit"
	thirdNode   = "node-third"
	lineA       = "line-a-uuid"
	lineB       = "line-b-uuid"
	lineC       = "line-c-uuid"
	entryPublic = "203.0.113.10"
	exitPublic  = "203.0.113.20"
	clientIP    = "198.51.100.7"
)

var t0 = time.Date(2026, 8, 26, 1, 38, 0, 0, time.UTC)

func chainOptions() Options {
	return Options{
		NodePublicIPs: map[string][]string{
			entryNode: {entryPublic},
			exitNode:  {exitPublic},
		},
	}
}

func entryRecord() model.ConnRecord {
	return model.ConnRecord{
		NodeID: entryNode, LineUUID: lineA, InboundTag: "mixed-in",
		LogID: 1001, CoreGeneration: 7,
		SrcIP: clientIP, SrcPort: 51514,
		DstHost: "example.com", DstPort: 443,
		StartedAt: t0,
	}
}

func exitRecord() model.ConnRecord {
	return model.ConnRecord{
		NodeID: exitNode, LineUUID: lineB, InboundTag: "vless-in",
		LogID: 2002, CoreGeneration: 3,
		// sing-box does not log the local port the upstream dialled from, so
		// this port is whatever the kernel picked and is never a join key.
		SrcIP: entryPublic, SrcPort: 40001,
		DstHost: "example.com", DstPort: 443,
		StartedAt: t0.Add(20 * time.Millisecond),
	}
}

func edgesAB() []Edge { return []Edge{{SourceLineUUID: lineA, TargetLineUUID: lineB}} }

func key(r model.ConnRecord) model.ConnRecordKey {
	return model.ConnRecordKey{NodeID: r.NodeID, CoreGeneration: r.CoreGeneration, LogID: r.LogID}
}

// findPath returns the path whose first record key is head.
func findPath(t *testing.T, paths []model.HopPath, head model.ConnRecordKey) model.HopPath {
	t.Helper()
	for _, p := range paths {
		if len(p.RecordKeys) > 0 && p.RecordKeys[0] == head {
			return p
		}
	}
	t.Fatalf("no path headed by %+v in %+v", head, paths)
	return model.HopPath{}
}

// assertCoversEveryRecordOnce is the invariant a caller depends on when it
// stamps HopPathID: no record may sit in two paths, and none may be dropped.
func assertCoversEveryRecordOnce(t *testing.T, records []model.ConnRecord, paths []model.HopPath) {
	t.Helper()
	seen := map[model.ConnRecordKey]int{}
	for _, p := range paths {
		for _, k := range p.RecordKeys {
			seen[k]++
		}
	}
	for _, r := range records {
		if got := seen[key(r)]; got != 1 {
			t.Fatalf("record %+v appears in %d paths, want exactly 1", key(r), got)
		}
	}
	if len(seen) != len(records) {
		t.Fatalf("paths cover %d distinct records, want %d", len(seen), len(records))
	}
}

func TestStitchTwoHopInferred(t *testing.T) {
	entry, exit := entryRecord(), exitRecord()
	records := []model.ConnRecord{entry, exit}

	paths := Stitch(records, edgesAB(), chainOptions())

	assertCoversEveryRecordOnce(t, records, paths)
	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1: %+v", len(paths), paths)
	}
	p := paths[0]
	if p.Confidence != model.HopConfidenceInferred {
		t.Fatalf("confidence = %q, want %q", p.Confidence, model.HopConfidenceInferred)
	}
	want := []model.ConnRecordKey{key(entry), key(exit)}
	if !reflect.DeepEqual(p.RecordKeys, want) {
		t.Fatalf("hop order = %+v, want %+v", p.RecordKeys, want)
	}
	if len(p.Candidates) != 0 {
		t.Fatalf("an inferred path must carry no candidates, got %+v", p.Candidates)
	}
	if p.ID == "" {
		t.Fatal("path has no id")
	}
}

func TestStitchAmbiguousListsBothCandidates(t *testing.T) {
	entry := entryRecord()
	exit1 := exitRecord()
	exit2 := exitRecord()
	exit2.LogID = 2003
	exit2.StartedAt = t0.Add(30 * time.Millisecond)
	records := []model.ConnRecord{entry, exit1, exit2}

	paths := Stitch(records, edgesAB(), chainOptions())

	assertCoversEveryRecordOnce(t, records, paths)
	p := findPath(t, paths, key(entry))
	if p.Confidence != model.HopConfidenceAmbiguous {
		t.Fatalf("confidence = %q, want %q", p.Confidence, model.HopConfidenceAmbiguous)
	}
	if !reflect.DeepEqual(p.RecordKeys, []model.ConnRecordKey{key(entry)}) {
		t.Fatalf("an ambiguous path must not pick a hop, got %+v", p.RecordKeys)
	}
	wantCands := []model.ConnRecordKey{key(exit1), key(exit2)}
	if !reflect.DeepEqual(p.Candidates, wantCands) {
		t.Fatalf("candidates = %+v, want both exits %+v", p.Candidates, wantCands)
	}
	// Neither candidate may be swallowed: each is still its own unjoined path.
	for _, exit := range []model.ConnRecord{exit1, exit2} {
		q := findPath(t, paths, key(exit))
		if q.Confidence != model.HopConfidenceNone || len(q.RecordKeys) != 1 {
			t.Fatalf("candidate %+v should stand alone, got %+v", key(exit), q)
		}
	}
}

func TestStitchContestedDownstreamIsAmbiguousBothWays(t *testing.T) {
	// Two entries and one exit: the exit matches both, and there is no evidence
	// saying which entry produced it. Handing it to the first would be a guess.
	entry1 := entryRecord()
	entry2 := entryRecord()
	entry2.LogID = 1002
	entry2.SrcPort = 51515
	exit := exitRecord()
	records := []model.ConnRecord{entry1, entry2, exit}

	paths := Stitch(records, edgesAB(), chainOptions())

	assertCoversEveryRecordOnce(t, records, paths)
	for _, entry := range []model.ConnRecord{entry1, entry2} {
		p := findPath(t, paths, key(entry))
		if p.Confidence != model.HopConfidenceAmbiguous {
			t.Fatalf("entry %+v: confidence = %q, want %q", key(entry), p.Confidence, model.HopConfidenceAmbiguous)
		}
		if !reflect.DeepEqual(p.Candidates, []model.ConnRecordKey{key(exit)}) {
			t.Fatalf("entry %+v: candidates = %+v, want the contested exit", key(entry), p.Candidates)
		}
	}
}

func TestStitchNoMatchWindowExceeded(t *testing.T) {
	entry := entryRecord()
	exit := exitRecord()
	exit.StartedAt = t0.Add(DefaultWindow + time.Millisecond)

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())
}

func TestStitchNoMatchDownstreamStartsBeforeUpstream(t *testing.T) {
	entry := entryRecord()
	exit := exitRecord()
	exit.StartedAt = t0.Add(-time.Millisecond)

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())
}

func TestStitchNoMatchDestinationDiffers(t *testing.T) {
	entry := entryRecord()
	exit := exitRecord()
	exit.DstHost = "other.example"

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())

	portOnly := exitRecord()
	portOnly.DstPort = 8443
	assertNoJoin(t, []model.ConnRecord{entry, portOnly}, edgesAB(), chainOptions())
}

func TestStitchNoMatchMissingEdge(t *testing.T) {
	// Same evidence, no declared chain. The declared edge is the skeleton; a
	// coincidence of address and destination is not a chain.
	assertNoJoin(t, []model.ConnRecord{entryRecord(), exitRecord()}, nil, chainOptions())

	wrongWay := []Edge{{SourceLineUUID: lineB, TargetLineUUID: lineA}}
	assertNoJoin(t, []model.ConnRecord{entryRecord(), exitRecord()}, wrongWay, chainOptions())
}

func TestStitchNoMatchSrcIPIsNotTheUpstreamNode(t *testing.T) {
	entry := entryRecord()
	exit := exitRecord()
	exit.SrcIP = "203.0.113.99"

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())

	// And an upstream node with no known public address cannot be proven to be
	// the dialler at all.
	assertNoJoin(t, []model.ConnRecord{entry, exitRecord()}, edgesAB(), Options{})
}

func TestStitchNoMatchUnattributedLine(t *testing.T) {
	// Two records with no line uuid must not match each other on empty strings.
	entry := entryRecord()
	entry.LineUUID = ""
	exit := exitRecord()
	exit.LineUUID = ""

	assertNoJoin(t, []model.ConnRecord{entry, exit}, []Edge{{}}, chainOptions())
}

func assertNoJoin(t *testing.T, records []model.ConnRecord, edges []Edge, opts Options) {
	t.Helper()
	paths := Stitch(records, edges, opts)
	assertCoversEveryRecordOnce(t, records, paths)
	if len(paths) != len(records) {
		t.Fatalf("got %d paths, want one per record (%d): %+v", len(paths), len(records), paths)
	}
	for _, p := range paths {
		if p.Confidence != model.HopConfidenceNone {
			t.Fatalf("confidence = %q, want %q: %+v", p.Confidence, model.HopConfidenceNone, p)
		}
		if len(p.RecordKeys) != 1 {
			t.Fatalf("unjoined record must be a single-hop path, got %+v", p.RecordKeys)
		}
		if len(p.Candidates) != 0 {
			t.Fatalf("a none path must carry no candidates, got %+v", p.Candidates)
		}
	}
}

func TestStitchExactPromotionByCarriedIdentity(t *testing.T) {
	// carry_identity gives the downstream line its own credential per upstream
	// user, so hop 2 logs the end user. That is evidence, not inference: it
	// promotes to exact even though the src-ip and destination tests would both
	// fail here.
	entry := entryRecord()
	entry.UserID = "usr_alice"
	exit := exitRecord()
	exit.UserID = "usr_alice"
	exit.SrcIP = "192.0.2.77"
	exit.DstHost = "cdn.example"
	records := []model.ConnRecord{entry, exit}

	paths := Stitch(records, edgesAB(), chainOptions())

	assertCoversEveryRecordOnce(t, records, paths)
	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1: %+v", len(paths), paths)
	}
	if paths[0].Confidence != model.HopConfidenceExact {
		t.Fatalf("confidence = %q, want %q", paths[0].Confidence, model.HopConfidenceExact)
	}
	want := []model.ConnRecordKey{key(entry), key(exit)}
	if !reflect.DeepEqual(paths[0].RecordKeys, want) {
		t.Fatalf("hop order = %+v, want %+v", paths[0].RecordKeys, want)
	}
}

func TestStitchExactStillNeedsADeclaredEdge(t *testing.T) {
	entry := entryRecord()
	entry.UserID = "usr_alice"
	exit := exitRecord()
	exit.UserID = "usr_alice"

	assertNoJoin(t, []model.ConnRecord{entry, exit}, nil, chainOptions())
}

func TestStitchExactStillNeedsTheWindow(t *testing.T) {
	// The same user over the same chain hours later is a different flow.
	entry := entryRecord()
	entry.UserID = "usr_alice"
	exit := exitRecord()
	exit.UserID = "usr_alice"
	exit.StartedAt = t0.Add(2 * time.Hour)

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())
}

func TestStitchEmptyUserIDIsNotAnIdentityMatch(t *testing.T) {
	// Two unattributed records share the empty user id. That is not a match.
	entry := entryRecord()
	exit := exitRecord()
	exit.SrcIP = "192.0.2.77"

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())
}

func threeHopRecords() (model.ConnRecord, model.ConnRecord, model.ConnRecord) {
	entry := entryRecord()
	middle := exitRecord()
	last := model.ConnRecord{
		NodeID: thirdNode, LineUUID: lineC, InboundTag: "vless-in",
		LogID: 3003, CoreGeneration: 1,
		SrcIP: exitPublic, SrcPort: 40002,
		DstHost: "example.com", DstPort: 443,
		StartedAt: t0.Add(40 * time.Millisecond),
	}
	return entry, middle, last
}

func TestStitchThreeHopFold(t *testing.T) {
	entry, middle, last := threeHopRecords()
	records := []model.ConnRecord{entry, middle, last}
	edges := []Edge{
		{SourceLineUUID: lineA, TargetLineUUID: lineB},
		{SourceLineUUID: lineB, TargetLineUUID: lineC},
	}

	paths := Stitch(records, edges, chainOptions())

	assertCoversEveryRecordOnce(t, records, paths)
	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1 folded chain: %+v", len(paths), paths)
	}
	want := []model.ConnRecordKey{key(entry), key(middle), key(last)}
	if !reflect.DeepEqual(paths[0].RecordKeys, want) {
		t.Fatalf("hop order = %+v, want %+v", paths[0].RecordKeys, want)
	}
	if paths[0].Confidence != model.HopConfidenceInferred {
		t.Fatalf("confidence = %q, want %q", paths[0].Confidence, model.HopConfidenceInferred)
	}
}

func TestStitchFoldTakesTheWeakestLink(t *testing.T) {
	// Hop one carries identity, hop two is inferred. A chain is only as good as
	// its weakest join.
	entry, middle, last := threeHopRecords()
	entry.UserID = "usr_alice"
	middle.UserID = "usr_alice"
	records := []model.ConnRecord{entry, middle, last}
	edges := []Edge{
		{SourceLineUUID: lineA, TargetLineUUID: lineB},
		{SourceLineUUID: lineB, TargetLineUUID: lineC},
	}

	paths := Stitch(records, edges, chainOptions())

	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1: %+v", len(paths), paths)
	}
	if paths[0].Confidence != model.HopConfidenceInferred {
		t.Fatalf("confidence = %q, want %q", paths[0].Confidence, model.HopConfidenceInferred)
	}
	if len(paths[0].RecordKeys) != 3 {
		t.Fatalf("want a three record path, got %+v", paths[0].RecordKeys)
	}
}

func TestStitchFoldStopsAtAnAmbiguousLink(t *testing.T) {
	entry, middle, last := threeHopRecords()
	last2 := last
	last2.LogID = 3004
	last2.StartedAt = last.StartedAt.Add(time.Millisecond)
	records := []model.ConnRecord{entry, middle, last, last2}
	edges := []Edge{
		{SourceLineUUID: lineA, TargetLineUUID: lineB},
		{SourceLineUUID: lineB, TargetLineUUID: lineC},
	}

	paths := Stitch(records, edges, chainOptions())

	assertCoversEveryRecordOnce(t, records, paths)
	p := findPath(t, paths, key(entry))
	if p.Confidence != model.HopConfidenceAmbiguous {
		t.Fatalf("confidence = %q, want %q", p.Confidence, model.HopConfidenceAmbiguous)
	}
	if !reflect.DeepEqual(p.RecordKeys, []model.ConnRecordKey{key(entry), key(middle)}) {
		t.Fatalf("path should hold the decided hops only, got %+v", p.RecordKeys)
	}
	if !reflect.DeepEqual(p.Candidates, []model.ConnRecordKey{key(last), key(last2)}) {
		t.Fatalf("candidates = %+v, want both third hops", p.Candidates)
	}
}

func TestStitchCyclicEdgesTerminate(t *testing.T) {
	// The server rejects cyclic chains when it compiles them. If one ever
	// reaches here it must not hang, and every record must still come back.
	a := entryRecord()
	a.DstHost, a.DstPort = "example.com", 443

	b := exitRecord()
	b.SrcIP = entryPublic

	c := model.ConnRecord{
		NodeID: thirdNode, LineUUID: lineC, LogID: 3003,
		SrcIP: exitPublic, DstHost: "example.com", DstPort: 443,
		StartedAt: t0.Add(40 * time.Millisecond),
	}
	// Close the loop: the third node dials back into the entry line.
	back := model.ConnRecord{
		NodeID: entryNode, LineUUID: lineA, LogID: 1009,
		SrcIP: "203.0.113.30", DstHost: "example.com", DstPort: 443,
		StartedAt: t0.Add(60 * time.Millisecond),
	}
	opts := chainOptions()
	opts.NodePublicIPs[thirdNode] = []string{"203.0.113.30"}
	records := []model.ConnRecord{a, b, c, back}
	edges := []Edge{
		{SourceLineUUID: lineA, TargetLineUUID: lineB},
		{SourceLineUUID: lineB, TargetLineUUID: lineC},
		{SourceLineUUID: lineC, TargetLineUUID: lineA},
	}

	done := make(chan []model.HopPath, 1)
	go func() { done <- Stitch(records, edges, opts) }()
	select {
	case paths := <-done:
		assertCoversEveryRecordOnce(t, records, paths)
	case <-time.After(5 * time.Second):
		t.Fatal("Stitch did not terminate on a cyclic edge set")
	}
}

func TestStitchTightCycleTerminates(t *testing.T) {
	// The tightest possible loop: two records that each look like the other's
	// downstream, so the edge set leaves no head to start from. The walk must
	// stop at the record it already placed instead of circling.
	first := model.ConnRecord{
		NodeID: entryNode, LineUUID: lineA, LogID: 1,
		SrcIP: exitPublic, DstHost: "example.com", DstPort: 443,
		StartedAt: t0,
	}
	second := model.ConnRecord{
		NodeID: exitNode, LineUUID: lineB, LogID: 2,
		SrcIP: entryPublic, DstHost: "example.com", DstPort: 443,
		StartedAt: t0,
	}
	edges := []Edge{
		{SourceLineUUID: lineA, TargetLineUUID: lineB},
		{SourceLineUUID: lineB, TargetLineUUID: lineA},
	}
	records := []model.ConnRecord{first, second}

	done := make(chan []model.HopPath, 1)
	go func() { done <- Stitch(records, edges, chainOptions()) }()
	select {
	case paths := <-done:
		assertCoversEveryRecordOnce(t, records, paths)
		if len(paths) != 1 || len(paths[0].RecordKeys) != 2 {
			t.Fatalf("want one two record path, got %+v", paths)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stitch did not terminate on a tight cycle")
	}
}

func TestStitchSelfEdgeIsIgnored(t *testing.T) {
	entry := entryRecord()
	sibling := entryRecord()
	sibling.LogID = 1002
	sibling.SrcIP = entryPublic
	sibling.StartedAt = t0.Add(time.Millisecond)

	assertNoJoin(t, []model.ConnRecord{entry, sibling}, []Edge{{SourceLineUUID: lineA, TargetLineUUID: lineA}}, chainOptions())
}

func TestStitchIsDeterministic(t *testing.T) {
	entry, middle, last := threeHopRecords()
	extra := exitRecord()
	extra.LogID = 2077
	extra.DstHost = "unrelated.example"
	edges := []Edge{
		{SourceLineUUID: lineA, TargetLineUUID: lineB},
		{SourceLineUUID: lineB, TargetLineUUID: lineC},
	}

	ordered := []model.ConnRecord{entry, middle, last, extra}
	shuffled := []model.ConnRecord{extra, last, middle, entry}

	first := Stitch(ordered, edges, chainOptions())
	second := Stitch(ordered, edges, chainOptions())
	third := Stitch(shuffled, edges, chainOptions())

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated runs differ:\n%+v\n%+v", first, second)
	}
	if !reflect.DeepEqual(first, third) {
		t.Fatalf("input order changed the output:\n%+v\n%+v", first, third)
	}
	if ordered[0].LogID != entry.LogID || ordered[3].LogID != extra.LogID {
		t.Fatal("Stitch reordered the caller's slice")
	}
}

func TestStitchIDIsStableAndPerPath(t *testing.T) {
	entry, exit := entryRecord(), exitRecord()
	paths := Stitch([]model.ConnRecord{entry, exit}, edgesAB(), chainOptions())
	again := Stitch([]model.ConnRecord{exit, entry}, edgesAB(), chainOptions())

	if paths[0].ID != again[0].ID {
		t.Fatalf("id churned across runs: %q vs %q", paths[0].ID, again[0].ID)
	}

	// A different flow gets a different id.
	other := entryRecord()
	other.LogID = 1234
	solo := Stitch([]model.ConnRecord{other}, nil, chainOptions())
	if solo[0].ID == paths[0].ID {
		t.Fatal("distinct paths share an id")
	}

	// The id survives a confidence change: same records, same path.
	promoted := []model.ConnRecord{entry, exit}
	promoted[0].UserID, promoted[1].UserID = "usr_alice", "usr_alice"
	upgraded := Stitch(promoted, edgesAB(), chainOptions())
	if upgraded[0].Confidence != model.HopConfidenceExact {
		t.Fatalf("expected the promoted run to be exact, got %q", upgraded[0].Confidence)
	}
	if upgraded[0].ID != paths[0].ID {
		t.Fatalf("id changed when confidence improved: %q vs %q", upgraded[0].ID, paths[0].ID)
	}
}

func TestStitchWindowOverride(t *testing.T) {
	entry := entryRecord()
	exit := exitRecord()
	exit.StartedAt = t0.Add(10 * time.Second)

	opts := chainOptions()
	opts.Window = 30 * time.Second
	paths := Stitch([]model.ConnRecord{entry, exit}, edgesAB(), opts)

	if len(paths) != 1 || paths[0].Confidence != model.HopConfidenceInferred {
		t.Fatalf("a widened window should still join: %+v", paths)
	}
}

func TestStitchNormalisesIPv6Forms(t *testing.T) {
	entry := entryRecord()
	exit := exitRecord()
	exit.SrcIP = "2001:db8:0:0:0:0:0:1"
	opts := chainOptions()
	opts.NodePublicIPs[entryNode] = []string{"2001:0db8::1"}

	paths := Stitch([]model.ConnRecord{entry, exit}, edgesAB(), opts)
	if len(paths) != 1 || paths[0].Confidence != model.HopConfidenceInferred {
		t.Fatalf("equivalent IPv6 spellings should match: %+v", paths)
	}
}

func TestStitchRecordWithoutStartTimeNeverJoins(t *testing.T) {
	entry := entryRecord()
	entry.StartedAt = time.Time{}
	exit := exitRecord()
	exit.StartedAt = time.Time{}

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())
}

func TestStitchEmptyInput(t *testing.T) {
	if got := Stitch(nil, edgesAB(), chainOptions()); got != nil {
		t.Fatalf("want nil for no records, got %+v", got)
	}
}

func TestStitchDestinationPortMustBeKnown(t *testing.T) {
	// A record whose destination port never parsed has no destination key.
	// Equality between two unknowns is not evidence.
	entry := entryRecord()
	entry.DstPort = 0
	exit := exitRecord()
	exit.DstPort = 0

	assertNoJoin(t, []model.ConnRecord{entry, exit}, edgesAB(), chainOptions())
}

func TestStitchPublicAddressConfiguredAsAHostname(t *testing.T) {
	// NodePublicIPs is meant to hold addresses, but an operator can put a
	// hostname there. It then matches only itself, spelled either way.
	entry := entryRecord()
	exit := exitRecord()
	exit.SrcIP = "Entry.Example"
	opts := chainOptions()
	opts.NodePublicIPs[entryNode] = []string{"entry.example"}

	paths := Stitch([]model.ConnRecord{entry, exit}, edgesAB(), opts)
	if len(paths) != 1 || paths[0].Confidence != model.HopConfidenceInferred {
		t.Fatalf("hostname form should still match itself: %+v", paths)
	}
}

func TestStitchOrdersTiedTimestampsDeterministically(t *testing.T) {
	// Records sharing a start time still need one stable order, or the paths
	// and their ids would flicker between runs.
	a := model.ConnRecord{NodeID: exitNode, LineUUID: lineB, LogID: 5, CoreGeneration: 2, StartedAt: t0}
	b := model.ConnRecord{NodeID: exitNode, LineUUID: lineB, LogID: 4, CoreGeneration: 2, StartedAt: t0}
	c := model.ConnRecord{NodeID: exitNode, LineUUID: lineB, LogID: 9, CoreGeneration: 1, StartedAt: t0}
	d := model.ConnRecord{NodeID: entryNode, LineUUID: lineA, LogID: 7, CoreGeneration: 9, StartedAt: t0}

	paths := Stitch([]model.ConnRecord{a, b, c, d}, edgesAB(), chainOptions())

	want := []model.ConnRecordKey{key(d), key(c), key(b), key(a)}
	got := make([]model.ConnRecordKey, 0, len(paths))
	for _, p := range paths {
		got = append(got, p.RecordKeys[0])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path order = %+v, want %+v", got, want)
	}
}
