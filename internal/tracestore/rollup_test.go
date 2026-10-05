package tracestore

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func mustRollups(t *testing.T, s *Store, f RollupFilter) []Rollup {
	t.Helper()
	out, err := s.Rollups(f)
	if err != nil {
		t.Fatalf("Rollups: %v", err)
	}
	return out
}

// TestRollupsCountEveryConnectionButSumOnlyMeasuredBytes is the byte-honesty
// case. A connection shorter than the /connections sampling interval is never
// sampled, so its bytes are unknown rather than zero; summing those unknowns as
// zero is the exact lie this feature exists to prevent.
func TestRollupsCountEveryConnectionButSumOnlyMeasuredBytes(t *testing.T) {
	s := newStore(t, Options{})

	measured := rec("n1", 1, t0)
	measured.UserID, measured.LineUUID = "u1", "l1"
	measured.BytesKnown = true
	measured.Upload, measured.Download = 100, 200

	measuredZero := rec("n1", 2, t0)
	measuredZero.UserID, measuredZero.LineUUID = "u1", "l1"
	measuredZero.BytesKnown = true // measured, and genuinely moved nothing

	unmeasured := rec("n1", 3, t0)
	unmeasured.UserID, unmeasured.LineUUID = "u1", "l1"
	unmeasured.CloseReason = model.CloseReset
	unmeasured.Upload, unmeasured.Download = 7, 9 // present but never measured

	mustAppend(t, s, measured, measuredZero, unmeasured)

	got := mustRollups(t, s, RollupFilter{})
	if len(got) != 1 {
		t.Fatalf("got %d buckets, want 1: %+v", len(got), got)
	}
	r := got[0]
	if r.Connections != 3 {
		t.Errorf("Connections = %d, want 3: an unmeasured connection still happened", r.Connections)
	}
	if r.BytesKnownCount != 2 {
		t.Errorf("BytesKnownCount = %d, want 2", r.BytesKnownCount)
	}
	if r.Upload != 100 || r.Download != 200 {
		t.Errorf("bytes = %d up / %d down, want 100 / 200: unmeasured bytes must not be summed", r.Upload, r.Download)
	}
	want := map[string]int64{model.CloseEOF: 2, model.CloseReset: 1}
	if len(r.CloseReasons) != len(want) {
		t.Fatalf("close reasons = %v, want %v", r.CloseReasons, want)
	}
	var total int64
	for reason, n := range want {
		if r.CloseReasons[reason] != n {
			t.Errorf("close reason %q = %d, want %d", reason, r.CloseReasons[reason], n)
		}
		total += r.CloseReasons[reason]
	}
	if total != r.Connections {
		t.Errorf("close reasons sum to %d but Connections is %d", total, r.Connections)
	}
}

func TestRollupsNameAnAbsentCloseReasonUnknown(t *testing.T) {
	s := newStore(t, Options{})
	r := rec("n1", 1, t0)
	r.CloseReason = "" // a final record whose last line said nothing
	mustAppend(t, s, r)
	got := mustRollups(t, s, RollupFilter{})
	if len(got) != 1 || got[0].CloseReasons[model.CloseUnknown] != 1 {
		t.Fatalf("rollup = %+v, want one connection counted as unknown", got)
	}
}

func TestRollupsIgnoreOpenSnapshots(t *testing.T) {
	s := newStore(t, Options{})
	// The same connection snapshots four times before it ends. If snapshots
	// contributed, a long-lived connection would count once per minute forever.
	for i := range 4 {
		snap := rec("n1", 1, t0)
		snap.Open = true
		snap.CloseReason = ""
		snap.EndedAt = time.Time{}
		snap.BytesKnown = true
		snap.Upload = int64(100 * (i + 1))
		mustAppend(t, s, snap)
	}
	if got := mustRollups(t, s, RollupFilter{}); len(got) != 0 {
		t.Fatalf("open snapshots produced rollups: %+v", got)
	}
	final := rec("n1", 1, t0)
	final.BytesKnown = true
	final.Upload = 500
	mustAppend(t, s, final)

	got := mustRollups(t, s, RollupFilter{})
	if len(got) != 1 {
		t.Fatalf("got %d buckets, want 1", len(got))
	}
	if got[0].Connections != 1 || got[0].Upload != 500 || got[0].BytesKnownCount != 1 {
		t.Errorf("rollup = %+v, want one connection with 500 measured upload bytes", got[0])
	}
}

func TestRollupsBucketToFiveMinutes(t *testing.T) {
	s := newStore(t, Options{})
	base := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	mustAppend(t, s,
		rec("n1", 1, base.Add(1*time.Minute)),                // bucket 12:00
		rec("n1", 2, base.Add(4*time.Minute+59*time.Second)), // bucket 12:00
		rec("n1", 3, base.Add(5*time.Minute)),                // bucket 12:05
		rec("n1", 4, base.Add(11*time.Minute)),               // bucket 12:10
	)
	got := mustRollups(t, s, RollupFilter{})
	if len(got) != 3 {
		t.Fatalf("got %d buckets, want 3: %+v", len(got), got)
	}
	wantStarts := []time.Time{base, base.Add(5 * time.Minute), base.Add(10 * time.Minute)}
	wantCounts := []int64{2, 1, 1}
	for i, r := range got {
		if !r.BucketStart.Equal(wantStarts[i]) {
			t.Errorf("bucket %d starts at %v, want %v", i, r.BucketStart, wantStarts[i])
		}
		if r.Connections != wantCounts[i] {
			t.Errorf("bucket %d has %d connections, want %d", i, r.Connections, wantCounts[i])
		}
	}
}

func TestRollupsSplitByUserLineAndNode(t *testing.T) {
	s := newStore(t, Options{})
	mk := func(id uint32, node, user, line string, at time.Time) model.ConnRecord {
		r := rec(node, id, at)
		r.UserID, r.LineUUID = user, line
		return r
	}
	later := t0.Add(6 * time.Minute)
	mustAppend(t, s,
		mk(1, "n1", "u1", "l1", t0),
		mk(2, "n1", "u1", "l1", t0.Add(time.Minute)),
		mk(3, "n1", "u2", "l1", t0),
		mk(4, "n2", "u1", "l1", t0),
		mk(5, "n1", "u1", "l2", t0),
		mk(6, "n1", "u1", "l1", later),
	)
	if got := mustRollups(t, s, RollupFilter{}); len(got) != 5 {
		t.Fatalf("got %d buckets, want 5 (one per user/line/node/bucket combination): %+v", len(got), got)
	}

	cases := []struct {
		name            string
		f               RollupFilter
		wantBuckets     int
		wantConnections int64
	}{
		{"user", RollupFilter{UserIDs: []string{"u1"}}, 4, 5},
		{"line", RollupFilter{LineUUIDs: []string{"l1"}}, 4, 5},
		{"node", RollupFilter{NodeIDs: []string{"n1"}}, 4, 5},
		{"user and node", RollupFilter{UserIDs: []string{"u1"}, NodeIDs: []string{"n1"}}, 3, 4},
		{"since excludes the earlier bucket", RollupFilter{Since: later.Truncate(RollupBucket)}, 1, 1},
		{"until excludes the later bucket", RollupFilter{Until: t0}, 4, 5},
		{"nothing matches", RollupFilter{UserIDs: []string{"u9"}}, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustRollups(t, s, tc.f)
			if len(got) != tc.wantBuckets {
				t.Fatalf("got %d buckets, want %d: %+v", len(got), tc.wantBuckets, got)
			}
			var total int64
			for _, r := range got {
				total += r.Connections
			}
			if total != tc.wantConnections {
				t.Errorf("connections = %d, want %d", total, tc.wantConnections)
			}
		})
	}
}

func TestRollupsKeepUnattributedConnections(t *testing.T) {
	s := newStore(t, Options{})
	// No user could be resolved (auth_failed has no user name at all). The
	// connection still happened, so it still has to appear in the totals.
	r := rec("n1", 1, t0)
	r.CloseReason = model.CloseAuthFailed
	mustAppend(t, s, r)
	got := mustRollups(t, s, RollupFilter{})
	if len(got) != 1 || got[0].UserID != "" || got[0].Connections != 1 {
		t.Fatalf("rollup = %+v, want one bucket with an empty user id", got)
	}
}

func TestRollupsAreAscendingAndClamped(t *testing.T) {
	s := newStore(t, Options{})
	batch := make([]model.ConnRecord, 0, 12)
	for i := range 12 {
		batch = append(batch, rec("n1", uint32(i+1), t0.Add(time.Duration(i)*RollupBucket)))
	}
	mustAppend(t, s, batch...)
	got := mustRollups(t, s, RollupFilter{})
	if len(got) != 12 {
		t.Fatalf("got %d buckets, want 12", len(got))
	}
	for i := 1; i < len(got); i++ {
		if !got[i-1].BucketStart.Before(got[i].BucketStart) {
			t.Fatalf("buckets are not ascending at %d", i)
		}
	}
	if n := len(mustRollups(t, s, RollupFilter{Limit: 5})); n != 5 {
		t.Errorf("limit 5 returned %d buckets", n)
	}
	if n := len(mustRollups(t, s, RollupFilter{Limit: -1})); n != 12 {
		t.Errorf("a negative limit returned %d buckets, want the default page", n)
	}
}

func mustRollupSeries(t *testing.T, s *Store, f RollupSeriesFilter) ([]RollupPoint, time.Time, bool) {
	t.Helper()
	points, retainedFrom, truncated, err := s.RollupSeries(context.Background(), f)
	if err != nil {
		t.Fatalf("RollupSeries: %v", err)
	}
	return points, retainedFrom, truncated
}

// TestRollupSeriesCoarsensToTheStep sums every five-minute bucket inside one
// step into one point, per key, and leaves a step with nothing in it absent.
func TestRollupSeriesCoarsensToTheStep(t *testing.T) {
	s := newStore(t, Options{})
	hour := t0 // 12:00, on an hour boundary
	mk := func(id uint32, node string, at time.Time, reason string, up, down int64, known bool) model.ConnRecord {
		r := rec(node, id, at)
		r.CloseReason = reason
		r.BytesKnown, r.Upload, r.Download = known, up, down
		return r
	}
	mustAppend(t, s,
		mk(1, "n1", hour.Add(1*time.Minute), model.CloseEOF, 10, 100, true),
		mk(2, "n1", hour.Add(17*time.Minute), model.CloseReset, 5, 50, true),
		mk(3, "n1", hour.Add(59*time.Minute), model.CloseEOF, 99, 99, false),
		mk(4, "n2", hour.Add(30*time.Minute), model.CloseTimeout, 1, 2, true),
		// 13:00 is empty; 14:xx has one connection on n1.
		mk(5, "n1", hour.Add(2*time.Hour+5*time.Minute), model.CloseEOF, 7, 8, true),
	)
	points, _, truncated := mustRollupSeries(t, s, RollupSeriesFilter{
		Since: hour, Until: hour.Add(3 * time.Hour), Step: time.Hour, GroupBy: RollupGroupNode,
	})
	if truncated {
		t.Fatal("two keys under the default ceiling reported truncated")
	}
	type want struct {
		key                 string
		at                  time.Time
		conns, known, up, d int64
		reasons             map[string]int64
	}
	wants := []want{
		// n1 has four connections, n2 one, so n1's series comes first.
		{"n1", hour, 3, 2, 15, 150, map[string]int64{model.CloseEOF: 2, model.CloseReset: 1}},
		{"n1", hour.Add(2 * time.Hour), 1, 1, 7, 8, map[string]int64{model.CloseEOF: 1}},
		{"n2", hour, 1, 1, 1, 2, map[string]int64{model.CloseTimeout: 1}},
	}
	if len(points) != len(wants) {
		t.Fatalf("got %d points, want %d: %+v", len(points), len(wants), points)
	}
	for i, w := range wants {
		p := points[i]
		if p.Key != w.key || !p.BucketStart.Equal(w.at) {
			t.Fatalf("point %d is %s at %v, want %s at %v", i, p.Key, p.BucketStart, w.key, w.at)
		}
		if p.Connections != w.conns || p.BytesKnownCount != w.known || p.Upload != w.up || p.Download != w.d {
			t.Errorf("point %d = %+v, want conns %d known %d up %d down %d", i, p, w.conns, w.known, w.up, w.d)
		}
		if len(p.CloseReasons) != len(w.reasons) {
			t.Fatalf("point %d reasons = %v, want %v", i, p.CloseReasons, w.reasons)
		}
		for reason, n := range w.reasons {
			if p.CloseReasons[reason] != n {
				t.Errorf("point %d reason %s = %d, want %d", i, reason, p.CloseReasons[reason], n)
			}
		}
	}
}

// TestRollupSeriesTruncatesSinceToTheStep makes the leading step whole: a
// window that starts mid-step still counts the step it starts in from the
// step's beginning, rather than dropping or halving it.
func TestRollupSeriesTruncatesSinceToTheStep(t *testing.T) {
	s := newStore(t, Options{})
	mustAppend(t, s,
		rec("n1", 1, t0.Add(5*time.Minute)),
		rec("n1", 2, t0.Add(50*time.Minute)),
	)
	points, _, _ := mustRollupSeries(t, s, RollupSeriesFilter{
		Since: t0.Add(40 * time.Minute), Until: t0.Add(2 * time.Hour), Step: time.Hour, GroupBy: RollupGroupNode,
	})
	if len(points) != 1 || !points[0].BucketStart.Equal(t0) || points[0].Connections != 2 {
		t.Fatalf("points = %+v, want one point at %v with both connections", points, t0)
	}

	// Until is exclusive: a bucket starting exactly at Until is the next window's.
	points, _, _ = mustRollupSeries(t, s, RollupSeriesFilter{
		Since: t0, Until: t0.Add(5 * time.Minute), Step: RollupBucket, GroupBy: RollupGroupNode,
	})
	if len(points) != 0 {
		t.Fatalf("points = %+v, want none: the only buckets start at or after Until", points)
	}

	for _, bad := range []RollupSeriesFilter{
		{Since: t0, Until: t0.Add(time.Hour), Step: 7 * time.Minute, GroupBy: RollupGroupNode},
		{Since: t0, Until: t0.Add(time.Hour), Step: 0, GroupBy: RollupGroupNode},
		{Since: t0, Until: t0.Add(time.Hour), Step: time.Hour, GroupBy: "dst"},
		{Since: t0, Until: t0, Step: time.Hour, GroupBy: RollupGroupNode},
	} {
		if _, _, _, err := s.RollupSeries(context.Background(), bad); err == nil {
			t.Errorf("RollupSeries(%+v) accepted a bad request", bad)
		}
	}
}

// TestRollupSeriesReasonPassMatchesGoDecoding checks the series' reason sums,
// which come from a hand parser of close_reasons, against decodeReasons
// (encoding/json) over the same rows.
func TestRollupSeriesReasonPassMatchesGoDecoding(t *testing.T) {
	s := newStore(t, Options{})
	reasons := []string{model.CloseEOF, model.CloseReset, model.CloseTimeout, model.CloseAuthFailed, ""}
	batch := []model.ConnRecord{}
	for i := range 90 {
		r := rec([]string{"n1", "n2", "n3"}[i%3], uint32(i+1), t0.Add(time.Duration(i)*3*time.Minute))
		r.UserID = []string{"u1", "u2", ""}[i%3]
		r.CloseReason = reasons[i%len(reasons)]
		batch = append(batch, r)
	}
	mustAppend(t, s, batch...)

	want := map[string]int64{}
	for _, r := range mustRollups(t, s, RollupFilter{}) {
		for reason, n := range r.CloseReasons {
			want[reason] += n
		}
	}

	points, _, _ := mustRollupSeries(t, s, RollupSeriesFilter{
		Since: t0, Until: t0.Add(24 * time.Hour), Step: 24 * time.Hour, GroupBy: RollupGroupReason,
	})
	got := map[string]int64{}
	var total int64
	for _, p := range points {
		if len(p.CloseReasons) != 0 {
			t.Errorf("a reason point carries close reasons: %+v", p)
		}
		got[p.Key] += p.Connections
		total += p.Connections
	}
	if len(got) != len(want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
	for reason, n := range want {
		if got[reason] != n {
			t.Errorf("reason %q = %d, want %d", reason, got[reason], n)
		}
	}
	if total != int64(len(batch)) {
		t.Errorf("reason counts sum to %d, want %d connections", total, len(batch))
	}

	// The per-key reasons on a node series agree with the same decoding.
	byNode, _, _ := mustRollupSeries(t, s, RollupSeriesFilter{
		Since: t0, Until: t0.Add(24 * time.Hour), Step: 24 * time.Hour, GroupBy: RollupGroupUser,
	})
	seenUnattributed := false
	for _, p := range byNode {
		var sum int64
		for _, n := range p.CloseReasons {
			sum += n
		}
		if sum != p.Connections {
			t.Errorf("user %q: reasons sum to %d, connections %d", p.Key, sum, p.Connections)
		}
		if p.Key == "" {
			seenUnattributed = true
		}
	}
	if !seenUnattributed {
		t.Error("the unattributed user is missing from a per-user series")
	}
}

// TestRollupSeriesKeepsTheLargestKeys bounds the answer and keeps the series
// with the most connections, including the unattributed key when it is
// among them.
func TestRollupSeriesKeepsTheLargestKeys(t *testing.T) {
	s := newStore(t, Options{})
	batch := []model.ConnRecord{}
	id := uint32(0)
	add := func(user string, n int) {
		for range n {
			id++
			r := rec("n1", id, t0.Add(time.Duration(id)*time.Second))
			r.UserID = user
			batch = append(batch, r)
		}
	}
	add("", 5)
	add("u-big", 4)
	add("u-mid", 3)
	add("u-small", 1)
	mustAppend(t, s, batch...)

	points, _, truncated := mustRollupSeries(t, s, RollupSeriesFilter{
		Since: t0, Until: t0.Add(time.Hour), Step: time.Hour, GroupBy: RollupGroupUser, MaxSeries: 2,
	})
	if !truncated {
		t.Fatal("four keys under a ceiling of two were not reported truncated")
	}
	if len(points) != 2 || points[0].Key != "" || points[1].Key != "u-big" {
		t.Fatalf("points = %+v, want the unattributed key then u-big", points)
	}
}

// TestRollupSeriesRetainedFromFollowsTheNodes reports the oldest bucket held
// for the requested nodes, whatever the window.
func TestRollupSeriesRetainedFromFollowsTheNodes(t *testing.T) {
	s := newStore(t, Options{})
	mustAppend(t, s,
		rec("n1", 1, t0.Add(-48*time.Hour)),
		rec("n2", 2, t0.Add(-2*time.Hour)),
		rec("n2", 3, t0),
	)
	_, all, _ := mustRollupSeries(t, s, RollupSeriesFilter{Since: t0, Until: t0.Add(time.Hour), Step: time.Hour, GroupBy: RollupGroupNode})
	if want := t0.Add(-48 * time.Hour).Truncate(RollupBucket); !all.Equal(want) {
		t.Errorf("retained from %v, want %v", all, want)
	}
	_, n2, _ := mustRollupSeries(t, s, RollupSeriesFilter{Since: t0, Until: t0.Add(time.Hour), Step: time.Hour, GroupBy: RollupGroupNode, NodeIDs: []string{"n2", "n-none"}})
	if want := t0.Add(-2 * time.Hour); !n2.Equal(want) {
		t.Errorf("retained from for n2 = %v, want %v", n2, want)
	}
	_, none, _ := mustRollupSeries(t, s, RollupSeriesFilter{Since: t0, Until: t0.Add(time.Hour), Step: time.Hour, GroupBy: RollupGroupNode, NodeIDs: []string{"n-none"}})
	if !none.IsZero() {
		t.Errorf("retained from for a node with no rollups = %v, want zero", none)
	}
}

// TestRollupSeriesReadsAlikeThroughEitherPath reads one window both ways: a
// fleet-wide read over most of the span walks the table by rowid, while a
// read filtered to a few nodes goes through the per-node index. The answers
// must be identical, including rows written out of time order, which the
// rowid walk meets in insertion order.
func TestRollupSeriesReadsAlikeThroughEitherPath(t *testing.T) {
	s := newStore(t, Options{})
	nodes := []string{"n1", "n2", "n3"}
	reasons := []string{model.CloseEOF, model.CloseReset, model.CloseTimeout}
	batch := []model.ConnRecord{}
	for i := range 240 {
		// Every other record lands a day earlier than its neighbours, so
		// rowid order and bucket order disagree.
		at := t0.Add(time.Duration(i) * 7 * time.Minute)
		if i%2 == 1 {
			at = at.Add(-24 * time.Hour)
		}
		r := rec(nodes[i%3], uint32(i+1), at)
		r.UserID = []string{"u1", "u2", ""}[i%3]
		r.CloseReason = reasons[i%3]
		r.BytesKnown, r.Upload, r.Download = i%2 == 0, int64(i), int64(10*i)
		batch = append(batch, r)
	}
	for start := 0; start < len(batch); start += 40 {
		mustAppend(t, s, batch[start:start+40]...)
	}
	// The whole span, then a window that still covers most of it (so the
	// fleet-wide read still walks the table) but cuts off its first half day.
	for _, since := range []time.Time{t0.Add(-48 * time.Hour), t0.Add(-12 * time.Hour)} {
		window := RollupSeriesFilter{Since: since, Until: t0.Add(48 * time.Hour), Step: time.Hour, GroupBy: RollupGroupNode}
		walked, _, _ := mustRollupSeries(t, s, window)
		window.NodeIDs = nodes // three nodes: the per-node index path
		indexed, _, _ := mustRollupSeries(t, s, window)
		if len(walked) == 0 {
			t.Fatal("no points")
		}
		if !reflect.DeepEqual(walked, indexed) {
			t.Fatalf("since %v: the rowid walk and the index read disagree:\nwalk  %+v\nindex %+v", since, walked, indexed)
		}
		var total int64
		want := int64(0)
		for _, r := range batch {
			if !r.StartedAt.Before(since) {
				want++
			}
		}
		for _, p := range walked {
			total += p.Connections
		}
		if total != want {
			t.Errorf("since %v: points sum to %d connections, want %d", since, total, want)
		}
	}
}

// TestParseFlatCountsFallsBackOnAnythingUnexpected keeps the hand parser
// honest: it reads exactly the documents applyRollupDeltas writes and hands
// everything else to encoding/json.
func TestParseFlatCountsFallsBackOnAnythingUnexpected(t *testing.T) {
	for raw, want := range map[string]map[string]int64{
		`{}`:                    {},
		`{"eof":3,"reset":-1}`:  {"eof": 3, "reset": -1},
		`{"":2}`:                {"": 2},
		`{ "eof": 3 }`:          {"eof": 3},
		`{"e\u006ff":4}`:        {"eof": 4},
		`{"x":123456789012345}`: {"x": 123456789012345},
	} {
		got := map[string]int64{}
		if err := addReasonCounts(got, []byte(raw), func(b []byte) string { return string(b) }); err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", raw, got, want)
		}
	}
	for _, bad := range []string{`{"eof":1.5}`, `[1]`, `{"eof":"x"}`} {
		if err := addReasonCounts(map[string]int64{}, []byte(bad), func(b []byte) string { return string(b) }); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// TestRollupSeriesStopsWhenTheCallerLeaves: a read whose caller has gone
// returns the context's error rather than finishing the scan.
func TestRollupSeriesStopsWhenTheCallerLeaves(t *testing.T) {
	s := newStore(t, Options{})
	mustAppend(t, s, rec("n1", 1, t0), rec("n2", 2, t0.Add(time.Minute)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, f := range []RollupSeriesFilter{
		{Since: t0, Until: t0.Add(time.Hour), Step: time.Hour, GroupBy: RollupGroupNode},
		{Since: t0, Until: t0.Add(time.Hour), Step: time.Hour, GroupBy: RollupGroupNode, NodeIDs: []string{"n1"}},
	} {
		if _, _, _, err := s.RollupSeries(ctx, f); !errors.Is(err, context.Canceled) {
			t.Errorf("RollupSeries with a cancelled context = %v, want context.Canceled", err)
		}
	}
}

// TestRollupSeriesRefusesTooManyPoints: a read that would hold more points
// than its ceiling fails with ErrRollupTooManyPoints instead of growing.
func TestRollupSeriesRefusesTooManyPoints(t *testing.T) {
	s := newStore(t, Options{})
	batch := []model.ConnRecord{}
	for i := range 12 {
		r := rec("n1", uint32(i+1), t0.Add(time.Duration(i)*5*time.Minute))
		r.UserID = []string{"u1", "u2", "u3"}[i%3]
		batch = append(batch, r)
	}
	mustAppend(t, s, batch...)
	f := RollupSeriesFilter{Since: t0, Until: t0.Add(time.Hour), Step: RollupBucket, GroupBy: RollupGroupUser, MaxCells: 11}
	if _, _, _, err := s.RollupSeries(context.Background(), f); !errors.Is(err, ErrRollupTooManyPoints) {
		t.Fatalf("12 points under a ceiling of 11 = %v, want ErrRollupTooManyPoints", err)
	}
	f.MaxCells = 12
	if points, _, _, err := s.RollupSeries(context.Background(), f); err != nil || len(points) != 12 {
		t.Fatalf("12 points under a ceiling of 12 = %d points, %v", len(points), err)
	}
}
