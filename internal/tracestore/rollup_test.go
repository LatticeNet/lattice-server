package tracestore

import (
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
