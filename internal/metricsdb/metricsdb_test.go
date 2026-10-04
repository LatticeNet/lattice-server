package metricsdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

func openTest(t *testing.T, opts Options) (*DB, *clock, string) {
	t.Helper()
	c := &clock{t: t0}
	if opts.Now == nil {
		opts.Now = c.Now
	}
	path := filepath.Join(t.TempDir(), "metrics.db")
	db, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, c, path
}

func gauge(owner, name string, values ...float64) Sample {
	s := Sample{Owner: owner, Name: name, Kind: KindGauge}
	for _, v := range values {
		s.Gauge.Observe(v)
	}
	return s
}

func event(owner, name string, failed int, durations ...time.Duration) Sample {
	e := &Event{}
	for i, d := range durations {
		e.Observe(d, i < failed)
	}
	return Sample{Owner: owner, Name: name, Kind: KindEvent, Event: e}
}

func mustWrite(t *testing.T, db *DB, at time.Time, samples ...Sample) WriteResult {
	t.Helper()
	res, err := db.Write(at, samples)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// rowsFor counts an owner's rows in one tier.
func rowsFor(t *testing.T, db *DB, owner, tier string) int {
	t.Helper()
	db.mu.RLock()
	id, ok := db.owners[owner]
	db.mu.RUnlock()
	if !ok {
		return 0
	}
	n := 0
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte(tierPrefix + tier)).Cursor()
		prefix := ownerPrefix(id)
		for k, _ := c.Seek(prefix); k != nil && string(k[:4]) == string(prefix); k, _ = c.Next() {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWriteMergesARewrittenMinute(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	at := t0.Add(10*time.Minute + 20*time.Second)
	mustWrite(t, db, at, gauge("cp", "proc.rss", 100, 300), event("cp.http", "/api/nodes", 0, 10*time.Millisecond))
	// The same minute again: a shutdown flush and the first flush after the
	// restart both land in it, and they add up.
	mustWrite(t, db, at.Add(30*time.Second), gauge("cp", "proc.rss", 50), event("cp.http", "/api/nodes", 1, 30*time.Millisecond))
	c.Set(t0.Add(11 * time.Minute))
	res, err := db.Query("cp", []string{"proc.rss"}, t0, t0.Add(11*time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier.Name != "1m" || len(res.Series) != 1 || len(res.Series[0].Points) != 1 {
		t.Fatalf("query = %+v", res)
	}
	g := res.Series[0].Points[0].Gauge
	if g.Count != 3 || g.Min != 50 || g.Max != 300 || g.Sum != 450 {
		t.Fatalf("merged gauge = %+v, want count 3 min 50 max 300 sum 450", g)
	}
	if got := res.Series[0].Points[0].At; !got.Equal(t0.Add(10 * time.Minute)) {
		t.Fatalf("bucket at %v, want the minute start", got)
	}
	ev, _, err := db.Aggregate("cp.http", nil, t0, t0.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if e := ev["/api/nodes"].Event; e == nil || e.Count != 2 || e.Errors != 1 {
		t.Fatalf("merged event = %+v", e)
	}
}

func TestTierRollover(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	// Two hours and five minutes of minutes: every minute's rss is its index.
	minutes := 125
	for i := 0; i < minutes; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), gauge("cp", "proc.rss", float64(i)), event("plugin/x", "svc/m", 0, time.Duration(i+1)*time.Millisecond))
	}
	c.Set(t0.Add(time.Duration(minutes) * time.Minute))
	if got := rowsFor(t, db, "cp", "5m"); got != minutes/5 {
		t.Fatalf("5m rows = %d, want %d", got, minutes/5)
	}
	if got := rowsFor(t, db, "cp", "1h"); got != 2 {
		t.Fatalf("1h rows = %d, want 2 (the third hour has not closed)", got)
	}
	if got := rowsFor(t, db, "cp", "1d"); got != 0 {
		t.Fatalf("1d rows = %d, want 0", got)
	}
	// The second hour's bucket is minutes 60..119, rolled from 5m rows that
	// were rolled from 1m rows.
	db.mu.RLock()
	owner := db.owners["cp"]
	db.mu.RUnlock()
	var hour Point
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(tierPrefix + "1h")).Get(ownerKey(owner, t0.Add(time.Hour).Unix()))
		return decodeRow(v, nil, func(_ uint32, p Point) { hour = p })
	}); err != nil {
		t.Fatal(err)
	}
	if g := hour.Gauge; g.Count != 60 || g.Min != 60 || g.Max != 119 || g.Sum != float64((60+119)*60/2) {
		t.Fatalf("hour bucket = %+v, want 60 samples from 60 to 119", g)
	}
	// The event series rolled the same way, histogram and all.
	agg, tier, err := db.Aggregate("plugin/x", []string{"svc/m"}, t0, t0.Add(time.Duration(minutes)*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if tier.Name != "1m" || agg["svc/m"].Event.Count != uint32(minutes) {
		t.Fatalf("aggregate from %s = %+v", tier.Name, agg["svc/m"].Event)
	}
}

func TestRetentionTrimsEachTier(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	db.bolt.NoSync = true
	mustWrite(t, db, t0, gauge("cp", "load1", 1))
	// A write every 30 minutes for 49 hours: by the end the 1m bucket at t0
	// has aged out, while the 5m, 1h and 1d buckets it rolled into are
	// still inside their retention.
	end := t0.Add(49 * time.Hour)
	for at := t0.Add(30 * time.Minute); !at.After(end); at = at.Add(30 * time.Minute) {
		c.Set(at)
		mustWrite(t, db, at, gauge("cp", "load1", 2))
	}
	has := func(tier string, at time.Time) bool {
		t.Helper()
		db.mu.RLock()
		owner := db.owners["cp"]
		db.mu.RUnlock()
		found := false
		if err := db.bolt.View(func(tx *bolt.Tx) error {
			found = tx.Bucket([]byte(tierPrefix+tier)).Get(ownerKey(owner, at.Unix())) != nil
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return found
	}
	if has("1m", t0) {
		t.Fatal("the 1m bucket at t0 outlived its 48 hours")
	}
	if !has("1m", t0.Add(2*time.Hour)) {
		t.Fatal("a 1m bucket inside the 48 hours was trimmed")
	}
	if got := rowsFor(t, db, "cp", "1m"); got != 96 {
		t.Fatalf("1m rows = %d, want the 96 half-hours inside 48 hours", got)
	}
	for _, tier := range []string{"5m", "1h", "1d"} {
		if !has(tier, t0) {
			t.Fatalf("the %s bucket at t0 was trimmed inside its retention", tier)
		}
	}
}

// TestAClockAheadForSeveralFlushesKeepsHistory steps the clock a year ahead
// for one, two and ten consecutive flushes on top of three days of minutes,
// then brings it back. Each flush made ahead may cost at most an hour of the
// finest tier and roll at most an hour of buckets; once the clock is back the
// last rolled buckets are at most that far ahead of it, the buckets it fills
// meanwhile come out whole, and the rollup follows the clock once it passes
// them.
func TestAClockAheadForSeveralFlushesKeepsHistory(t *testing.T) {
	for _, flushes := range []int{1, 2, 10} {
		t.Run(fmt.Sprintf("%d flushes", flushes), func(t *testing.T) {
			db, c, _ := openTest(t, Options{})
			db.bolt.NoSync = true
			const minutes = 3 * 24 * 60
			for i := 0; i < minutes; i++ {
				at := t0.Add(time.Duration(i) * time.Minute)
				c.Set(at)
				mustWrite(t, db, at, gauge("cp", "x", 1))
			}
			before := map[string]int{}
			for _, tier := range DefaultTiers {
				before[tier.Name] = rowsFor(t, db, "cp", tier.Name)
			}
			yearAhead := t0.Add(minutes*time.Minute + 365*24*time.Hour)
			for i := 0; i < flushes; i++ {
				res := mustWrite(t, db, yearAhead.Add(time.Duration(i)*time.Minute), gauge("cp", "x", 2))
				// An hour of 5m buckets, and a bucket or two of the others.
				if res.Rolled > 20 {
					t.Fatalf("flush %d with the clock ahead rolled %d buckets", i, res.Rolled)
				}
			}
			back := t0.Add(minutes * time.Minute)
			c.Set(back)
			mustWrite(t, db, back, gauge("cp", "x", 3))

			// The finest tier lost at most an hour a flush, plus the minute
			// written each time; the coarser tiers lost nothing.
			if got, floor := rowsFor(t, db, "cp", "1m"), before["1m"]-60*flushes; got < floor {
				t.Fatalf("1m rows %d (was %d), want at least %d", got, before["1m"], floor)
			}
			for _, tier := range []string{"5m", "1h", "1d"} {
				if got := rowsFor(t, db, "cp", tier); got < before[tier] {
					t.Fatalf("%s rows %d, was %d before the clock fault", tier, got, before[tier])
				}
			}
			ahead := back.Add(time.Duration(flushes) * time.Hour)
			db.mu.RLock()
			rolled := append([]int64(nil), db.rolled...)
			db.mu.RUnlock()
			for i, tier := range DefaultTiers[1:] {
				if rolled[i+1] >= ahead.Unix() {
					t.Fatalf("tier %s last rolled %s, more than %d h ahead of the clock (%s)", tier.Name, time.Unix(rolled[i+1], 0).UTC(), flushes, back)
				}
			}
			// The clock runs on past those buckets. What it writes meanwhile
			// is re-rolled as it lands, so every 5m bucket comes out whole.
			end := ahead.Add(10 * time.Minute)
			for at := back.Add(time.Minute); at.Before(end); at = at.Add(time.Minute) {
				c.Set(at)
				mustWrite(t, db, at, gauge("cp", "x", 3))
			}
			db.mu.RLock()
			owner := db.owners["cp"]
			last5m := db.rolled[1]
			db.mu.RUnlock()
			for at := back; at.Add(5 * time.Minute).Before(end); at = at.Add(5 * time.Minute) {
				var g Gauge
				if err := db.bolt.View(func(tx *bolt.Tx) error {
					return decodeRow(tx.Bucket([]byte(tierPrefix+"5m")).Get(ownerKey(owner, at.Unix())), nil, func(_ uint32, p Point) { g = p.Gauge })
				}); err != nil {
					t.Fatal(err)
				}
				if g.Count != 5 || g.Sum != 15 {
					t.Fatalf("5m bucket %s after the clock came back = %+v, want 5 samples of 3", at, g)
				}
			}
			// And past them the rollup follows the clock again.
			if want := floorUnix(end.Unix(), 5*time.Minute) - 300; last5m != want {
				t.Fatalf("5m last rolled %s, want %s", time.Unix(last5m, 0).UTC(), time.Unix(want, 0).UTC())
			}
		})
	}
}

// TestALateWriteCannotReplaceACoarseBucket steps the clock back past what the
// finest tier still holds. Rolling the 5m bucket again would rebuild it from
// the one late minute and throw away the five it held, so the write is
// refused and counted. A late write the finest tier still covers is stored
// and re-rolled whole.
func TestALateWriteCannotReplaceACoarseBucket(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	db.bolt.NoSync = true
	// Four days and two minutes, so the 48-hour line falls inside a 5m
	// bucket.
	const minutes = 4*24*60 + 2
	for i := 0; i < minutes; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		c.Set(at)
		mustWrite(t, db, at, gauge("cp", "x", 10))
	}
	now := t0.Add(minutes * time.Minute)
	read5m := func(at time.Time) Gauge {
		t.Helper()
		db.mu.RLock()
		owner := db.owners["cp"]
		db.mu.RUnlock()
		var g Gauge
		if err := db.bolt.View(func(tx *bolt.Tx) error {
			return decodeRow(tx.Bucket([]byte(tierPrefix+"5m")).Get(ownerKey(owner, at.Unix())), nil, func(_ uint32, p Point) { g = p.Gauge })
		}); err != nil {
			t.Fatal(err)
		}
		return g
	}
	cases := []struct {
		name string
		at   time.Time
	}{
		// Three days back: the finest tier holds nothing of that bucket.
		{"three days back", now.Add(-72 * time.Hour)},
		// On the 48-hour line: the minute is still held, but the first
		// two minutes of its 5m bucket are not.
		{"straddling the 48-hour line", now.Add(-48 * time.Hour)},
	}
	for _, tc := range cases {
		bucket := time.Unix(floorUnix(tc.at.Unix(), 5*time.Minute), 0)
		if got := read5m(bucket); got.Count != 5 || got.Sum != 50 {
			t.Fatalf("%s: setup 5m bucket = %+v", tc.name, got)
		}
		res := mustWrite(t, db, tc.at, gauge("cp", "x", 99))
		if res.Late != 1 || res.Points != 0 {
			t.Fatalf("%s: write = %+v, want it refused as late", tc.name, res)
		}
		if got := read5m(bucket); got.Count != 5 || got.Sum != 50 {
			t.Fatalf("%s: 5m bucket after the late write = %+v, want it untouched", tc.name, got)
		}
	}
	// Two minutes later in the same hour the bucket is whole in the finest
	// tier: stored and re-rolled.
	inside := now.Add(-48*time.Hour + 5*time.Minute)
	if res := mustWrite(t, db, inside, gauge("cp", "x", 99)); res.Late != 0 || res.Points != 1 {
		t.Fatalf("covered late write = %+v, want it stored", res)
	}
	if got := read5m(time.Unix(floorUnix(inside.Unix(), 5*time.Minute), 0)); got.Count != 6 || got.Sum != 149 {
		t.Fatalf("5m bucket after a covered late write = %+v, want 6 samples summing to 149", got)
	}
	if st, _ := db.Stats(); st.LateSamples != 2 {
		t.Fatalf("late samples = %d, want 2", st.LateSamples)
	}
}

func TestTrimmingAndRollingCatchUpAfterDowntime(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	db.bolt.NoSync = true
	mustWrite(t, db, t0, gauge("cp", "x", 1))
	// Back three days later with a correct clock: the old minute is past
	// the 48-hour retention, but the horizon moves an hour per write.
	later := t0.Add(72 * time.Hour)
	c.Set(later)
	mustWrite(t, db, later, gauge("cp", "x", 2))
	if got := rowsFor(t, db, "cp", "1m"); got != 2 {
		t.Fatalf("first write after downtime: 1m rows = %d, want 2 (trim held back)", got)
	}
	// While the rollup catches up, a week's chart still reaches the minute
	// just written: the part not rolled yet is read from the finest tier.
	c.Set(later.Add(time.Minute))
	res, err := db.Query("cp", []string{"x"}, later.Add(-7*24*time.Hour), later.Add(time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if pts := res.Series[0].Points; len(pts) != 2 || pts[len(pts)-1].Gauge.Max != 2 {
		t.Fatalf("week chart during catch-up = %+v, want t0 and the new minute", pts)
	}
	for i := 1; i <= 80; i++ {
		at := later.Add(time.Duration(i) * time.Minute)
		c.Set(at)
		mustWrite(t, db, at, gauge("cp", "x", 3))
	}
	if got := rowsFor(t, db, "cp", "1m"); got != 81 {
		t.Fatalf("after catching up: 1m rows = %d, want only the 81 recent minutes", got)
	}
	db.mu.RLock()
	last5m := db.rolled[1]
	db.mu.RUnlock()
	if want := floorUnix(later.Add(81*time.Minute).Unix(), 5*time.Minute) - 300; last5m != want {
		t.Fatalf("5m last rolled %s, want %s", time.Unix(last5m, 0).UTC(), time.Unix(want, 0).UTC())
	}
	// The t0 point survives in the coarser tiers.
	if got := rowsFor(t, db, "cp", "1h"); got < 2 {
		t.Fatalf("1h rows = %d, want t0's hour and the new ones", got)
	}
}

// smallTiers keep the bounded-size test fast: the same shape as the
// defaults, in seconds instead of minutes.
var smallTiers = []Tier{
	{Name: "a", Res: time.Second, Keep: 10 * time.Second},
	{Name: "b", Res: 5 * time.Second, Keep: 60 * time.Second},
	{Name: "c", Res: 30 * time.Second, Keep: 300 * time.Second},
}

func TestRowsPerSeriesStayBounded(t *testing.T) {
	db, c, path := openTest(t, Options{Tiers: smallTiers})
	// Two thousand commits: skip the fsync, which is not what this measures.
	db.bolt.NoSync = true
	var sizes []int64
	for i := 0; i < 2000; i++ {
		at := t0.Add(time.Duration(i) * time.Second)
		c.Set(at)
		mustWrite(t, db, at, gauge("node/a", "cpu", float64(i%100)), event("cp.http", "/api/x", 0, time.Millisecond))
		for _, tier := range smallTiers {
			for _, owner := range []string{"node/a", "cp.http"} {
				if got, limit := rowsFor(t, db, owner, tier.Name), tier.Slots()+1; got > limit {
					t.Fatalf("second %d: %s holds %d rows in %s, more than %d", i, owner, got, tier.Name, limit)
				}
			}
		}
		if i%400 == 399 {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			sizes = append(sizes, fi.Size())
		}
	}
	// Retention frees pages that later writes reuse: once every tier is
	// full the file stops growing.
	if sizes[len(sizes)-1] != sizes[len(sizes)-2] {
		t.Fatalf("file kept growing after every tier filled: %v", sizes)
	}
}

func TestCardinalityCap(t *testing.T) {
	db, _, _ := openTest(t, Options{MaxSeries: 5, MaxSeriesPerOwner: 3})
	var samples []Sample
	for i := 0; i < 4; i++ {
		samples = append(samples, gauge("node/a", fmt.Sprintf("m%d", i), 1))
	}
	for i := 0; i < 3; i++ {
		samples = append(samples, gauge("node/b", fmt.Sprintf("m%d", i), 1))
	}
	res := mustWrite(t, db, t0, samples...)
	// node/a keeps three (its own cap), node/b two (the total cap).
	if res.Refused != 2 || res.Points != 5 {
		t.Fatalf("write = %+v, want 5 points and 2 refused", res)
	}
	st, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Series != 5 || st.RefusedSamples != 2 || len(st.RefusedSeries) != 2 {
		t.Fatalf("stats = %+v", st)
	}
	if r := st.RefusedSeries[0]; r.Owner != "node/a" || r.Name != "m3" || r.Reason != RefusedOwnerCap {
		t.Fatalf("first refused = %+v, want node/a m3 by its own cap", r)
	}
	if r := st.RefusedSeries[1]; r.Owner != "node/b" || r.Name != "m2" || r.Reason != RefusedTotalCap {
		t.Fatalf("second refused = %+v, want node/b m2 by the total cap", r)
	}
	// A known series keeps writing at the cap; a new one is still refused.
	res = mustWrite(t, db, t0.Add(time.Minute), gauge("node/a", "m0", 2), gauge("node/c", "m0", 2))
	if res.Points != 1 || res.Refused != 1 {
		t.Fatalf("second write = %+v, want the known series kept and the new one refused", res)
	}
	// Deleting an owner frees its share of the cap, and forgets what was
	// refused for it.
	if n, err := db.DeleteOwner("node/a"); err != nil || n != 3 {
		t.Fatalf("delete = %d, %v", n, err)
	}
	res = mustWrite(t, db, t0.Add(2*time.Minute), gauge("node/c", "m0", 3))
	if res.Points != 1 || res.Refused != 0 {
		t.Fatalf("write after delete = %+v", res)
	}
	st, _ = db.Stats()
	for _, r := range st.RefusedSeries {
		if r.Owner == "node/a" || (r.Owner == "node/c" && r.Name == "m0") {
			t.Fatalf("refused list still names %+v after it was deleted or stored", r)
		}
	}
}

// TestRefusedSeriesAreNamedOnce counts a refused series once however many
// flushes it is refused in, says why, reports it as new only the first time,
// and forgets it a day after its last refused sample.
func TestRefusedSeriesAreNamedOnce(t *testing.T) {
	db, _, _ := openTest(t, Options{MaxSeries: 2})
	mustWrite(t, db, t0, gauge("cp", "a", 1), event("cp", "b", 0, time.Millisecond))
	var fresh int
	for i := 1; i <= 10; i++ {
		res := mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute),
			gauge("cp", "a", 1), gauge("cp", "c", 1), // c: past the total cap
			gauge("cp", "b", 1), // b exists as an event
			gauge("cp", "bad\x00name", 1))
		fresh += len(res.NewlyRefused)
		if res.Refused != 3 || res.Points != 1 {
			t.Fatalf("flush %d = %+v, want 1 point and 3 refused", i, res)
		}
	}
	if fresh != 3 {
		t.Fatalf("newly refused %d times over ten flushes, want 3 (each series once)", fresh)
	}
	st, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, r := range st.RefusedSeries {
		reasons[r.Name] = r.Reason
		if r.Samples != 10 || !r.First.Equal(t0.Add(time.Minute)) || !r.Last.Equal(t0.Add(10*time.Minute)) {
			t.Fatalf("refused %+v, want 10 samples from minute 1 to minute 10", r)
		}
	}
	want := map[string]string{"c": RefusedTotalCap, "b": RefusedKindMismatch, "bad�name": RefusedInvalid}
	if len(reasons) != len(want) {
		t.Fatalf("refused = %v, want %v", reasons, want)
	}
	for name, reason := range want {
		if reasons[name] != reason {
			t.Fatalf("refused = %v, want %v", reasons, want)
		}
	}
	if st.RefusedSamples != 30 || st.RefusedSeriesMore {
		t.Fatalf("refused samples %d more %v, want 30 and false", st.RefusedSamples, st.RefusedSeriesMore)
	}
	// A day after the last refusal the list is empty again.
	mustWrite(t, db, t0.Add(10*time.Minute+refusedForget+time.Minute), gauge("cp", "a", 1))
	if st, _ = db.Stats(); len(st.RefusedSeries) != 0 {
		t.Fatalf("refused list after a quiet day = %+v", st.RefusedSeries)
	}
}

func TestRefusedSeriesListIsBounded(t *testing.T) {
	db, _, _ := openTest(t, Options{MaxSeries: 1})
	var samples []Sample
	for i := 0; i <= maxRefusedTracked+5; i++ {
		samples = append(samples, gauge("cp", fmt.Sprintf("s%03d", i), 1))
	}
	res := mustWrite(t, db, t0, samples...)
	if res.Refused != maxRefusedTracked+5 || len(res.NewlyRefused) != maxRefusedTracked {
		t.Fatalf("write refused %d, newly named %d", res.Refused, len(res.NewlyRefused))
	}
	st, _ := db.Stats()
	if len(st.RefusedSeries) != maxRefusedTracked || !st.RefusedSeriesMore {
		t.Fatalf("named %d refused series, more=%v; want %d and true", len(st.RefusedSeries), st.RefusedSeriesMore, maxRefusedTracked)
	}
}

func TestRestartKeepsDataCatalogAndRollups(t *testing.T) {
	c := &clock{t: t0}
	path := filepath.Join(t.TempDir(), "metrics.db")
	db, err := Open(path, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), gauge("node/n1", "cpu", float64(i)))
	}
	db.mu.RLock()
	idBefore := db.series[seriesKey{db.owners["node/n1"], "cpu"}].id
	rolledBefore := db.rolled[1]
	db.mu.RUnlock()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Write(t0, nil); err != ErrClosed {
		t.Fatalf("write after close = %v, want ErrClosed", err)
	}

	db, err = Open(path, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.mu.RLock()
	idAfter := db.series[seriesKey{db.owners["node/n1"], "cpu"}].id
	rolledAfter := db.rolled[1]
	db.mu.RUnlock()
	if idAfter != idBefore || rolledAfter != rolledBefore || rolledAfter != t0.Unix() {
		t.Fatalf("after reopen: id %d (was %d), rolled %d (was %d)", idAfter, idBefore, rolledAfter, rolledBefore)
	}
	// Writing after the restart continues the rollups without rolling the
	// first bucket twice into anything.
	for i := 7; i < 10; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), gauge("node/n1", "cpu", float64(i)))
	}
	c.Set(t0.Add(10 * time.Minute))
	res, err := db.Query("node/n1", nil, t0, t0.Add(10*time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Series) != 1 || len(res.Series[0].Points) != 10 {
		t.Fatalf("after restart query = %+v", res)
	}
	if got := rowsFor(t, db, "node/n1", "5m"); got != 2 {
		t.Fatalf("5m rows = %d, want 2", got)
	}
	agg, _, err := db.Aggregate("node/n1", nil, t0, t0.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if agg["cpu"].Gauge.Count != 10 || agg["cpu"].Gauge.Sum != 45 {
		t.Fatalf("aggregate = %+v", agg["cpu"].Gauge)
	}
}

func TestLateWriteRerollsClosedBuckets(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	for i := 0; i < 6; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), gauge("cp", "x", 1))
	}
	// Minute 2 arrives again after its 5m bucket rolled (a flush that a clock
	// step put in the past).
	mustWrite(t, db, t0.Add(2*time.Minute), gauge("cp", "x", 100))
	c.Set(t0.Add(6 * time.Minute))
	db.mu.RLock()
	owner := db.owners["cp"]
	db.mu.RUnlock()
	var p Point
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		return decodeRow(tx.Bucket([]byte(tierPrefix+"5m")).Get(ownerKey(owner, t0.Unix())), nil, func(_ uint32, got Point) { p = got })
	}); err != nil {
		t.Fatal(err)
	}
	if p.Gauge.Count != 6 || p.Gauge.Max != 100 {
		t.Fatalf("5m bucket after late write = %+v, want 6 samples with max 100", p.Gauge)
	}
}

func TestDeleteOwnerRemovesEveryTier(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	for i := 0; i < 65; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		mustWrite(t, db, at, gauge("node/gone", "cpu", 1), gauge("node/gone", "mem", 2), gauge("node/kept", "cpu", 3))
	}
	c.Set(t0.Add(65 * time.Minute))
	for _, tier := range []string{"1m", "5m", "1h"} {
		if rowsFor(t, db, "node/gone", tier) == 0 {
			t.Fatalf("setup: no %s rows", tier)
		}
	}
	n, err := db.DeleteOwner("node/gone")
	if err != nil || n != 2 {
		t.Fatalf("delete = %d, %v; want 2 series", n, err)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		for _, tier := range DefaultTiers {
			c := tx.Bucket([]byte(tierPrefix + tier.Name)).Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				if err := decodeRow(v, nil, func(series uint32, _ Point) {
					db.mu.RLock()
					ref, ok := db.seriesRefs[series]
					db.mu.RUnlock()
					if !ok || ref.name == "mem" {
						t.Errorf("%s row %x still holds series %d", tier.Name, k, series)
					}
				}); err != nil {
					return err
				}
			}
		}
		if tx.Bucket(bucketOwners).Get([]byte("node/gone")) != nil {
			t.Error("owner entry survived")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	owners, err := db.Owners()
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].Owner != "node/kept" || owners[0].Series != 1 {
		t.Fatalf("owners = %+v", owners)
	}
	if !owners[0].Newest.Equal(t0.Add(64 * time.Minute)) {
		t.Fatalf("newest = %v, want the last minute written", owners[0].Newest)
	}
	// The name can come back as a new owner with fresh series.
	mustWrite(t, db, t0.Add(66*time.Minute), gauge("node/gone", "cpu", 9))
	c.Set(t0.Add(67 * time.Minute))
	res, err := db.Query("node/gone", nil, t0, t0.Add(67*time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Series) != 1 || len(res.Series[0].Points) != 1 {
		t.Fatalf("reborn owner query = %+v", res)
	}
	// Prune by a rule: everything not "node/kept".
	gone, err := db.PruneOwners(func(owner string, _ time.Time) bool { return owner != "node/kept" })
	if err != nil || len(gone) != 1 || gone[0] != "node/gone" {
		t.Fatalf("prune = %v, %v", gone, err)
	}
}

func TestReopenWithFewerTiersDropsTheOrphan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	db, err := Open(path, Options{Tiers: smallTiers})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, db, t0, gauge("cp", "x", 1))
	db.Close()
	db, err = Open(path, Options{Tiers: smallTiers[:2]})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(tierPrefix+"c")) != nil {
			t.Error("tier c bucket survived a reopen without it")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsBadTiersAndNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	if _, err := Open(path, Options{Tiers: []Tier{{Name: "a", Res: time.Minute, Keep: time.Hour}, {Name: "b", Res: 90 * time.Second, Keep: 2 * time.Hour}}}); err == nil {
		t.Fatal("a tier that is not a multiple of the one below opened")
	}
	// A day bucket cannot be rolled from minutes kept for an hour.
	if _, err := Open(path, Options{Tiers: []Tier{{Name: "a", Res: time.Minute, Keep: time.Hour}, {Name: "b", Res: 24 * time.Hour, Keep: 30 * 24 * time.Hour}}}); err == nil {
		t.Fatal("a tier whose bucket outlasts the tier below opened")
	}
	db, _, _ := openTest(t, Options{})
	res := mustWrite(t, db, t0, gauge("", "x", 1), gauge("cp", "bad\x00name", 1), Sample{Owner: "cp", Name: "k", Kind: 9})
	if res.Refused != 3 || res.Points != 0 {
		t.Fatalf("write = %+v, want all three refused", res)
	}
	// One name, two kinds: the second kind is refused.
	mustWrite(t, db, t0, gauge("cp", "same", 1))
	res = mustWrite(t, db, t0.Add(time.Minute), event("cp", "same", 0, time.Millisecond))
	if res.Refused != 1 {
		t.Fatalf("kind change = %+v, want refused", res)
	}
}

func TestStatsDescribeTiersAndRows(t *testing.T) {
	db, _, path := openTest(t, Options{})
	mustWrite(t, db, t0, gauge("cp", "a", 1), gauge("cp", "b", 1))
	st, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Path != path || st.SizeBytes <= 0 || st.Series != 2 || st.Owners != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if st.SlotsPerSeries != 2880+4032+2160+1830 {
		t.Fatalf("slots per series = %d", st.SlotsPerSeries)
	}
	if len(st.Tiers) != 4 || st.Tiers[0].Rows != 1 || st.Tiers[0].ResolutionSeconds != 60 || st.Tiers[3].RetentionSeconds != 1830*86400 {
		t.Fatalf("tiers = %+v", st.Tiers)
	}
	if st.LastWrite.Points != 2 || st.LastWrite.Rows != 1 {
		t.Fatalf("last write = %+v", st.LastWrite)
	}
}

func TestCorruptCatalogFailsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	db, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(metaSchema, binary.BigEndian.AppendUint32(nil, 99))
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(path, Options{}); err == nil {
		t.Fatal("a schema from the future opened")
	}
}

// TestPruneIdleSeriesGivesThePlaceBack retires a series (a renamed route
// group, say): while any tier still holds a point of it, it stays; once every
// point has aged out, the prune drops it from the catalog and a new series
// can take its place under the owner's cap.
func TestPruneIdleSeriesGivesThePlaceBack(t *testing.T) {
	db, c, _ := openTest(t, Options{Tiers: smallTiers, MaxSeriesPerOwner: 2})
	db.bolt.NoSync = true
	write := func(i int, samples ...Sample) {
		t.Helper()
		at := t0.Add(time.Duration(i) * time.Second)
		c.Set(at)
		mustWrite(t, db, at, samples...)
	}
	for i := 0; i < 10; i++ {
		write(i, event("cp.http", "/api/old", 0, time.Millisecond), event("cp.http", "/api/kept", 0, time.Millisecond))
	}
	// Tier c keeps 300 s: at 100 s the old group still has points there.
	for i := 10; i < 100; i++ {
		write(i, event("cp.http", "/api/kept", 0, time.Millisecond))
	}
	if n, err := db.PruneIdleSeries(); err != nil || n != 0 {
		t.Fatalf("prune with points left = %d, %v; want nothing removed", n, err)
	}
	// The owner is at its cap, so a new group is refused.
	write(100, event("cp.http", "/api/new", 0, time.Millisecond))
	if st, _ := db.Stats(); st.Series != 2 || len(st.RefusedSeries) != 1 {
		t.Fatalf("at the cap: %d series, refused %+v", st.Series, st.RefusedSeries)
	}
	for i := 101; i < 400; i++ {
		write(i, event("cp.http", "/api/kept", 0, time.Millisecond))
	}
	n, err := db.PruneIdleSeries()
	if err != nil || n != 1 {
		t.Fatalf("prune after the old group aged out = %d, %v; want 1", n, err)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		db.mu.RLock()
		owner := db.owners["cp.http"]
		db.mu.RUnlock()
		if tx.Bucket(bucketSeries).Get(append(ownerPrefix(owner), "/api/old"...)) != nil {
			t.Error("the pruned series is still in the stored catalog")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	write(400, event("cp.http", "/api/new", 0, time.Millisecond))
	st, _ := db.Stats()
	if st.Series != 2 || len(st.RefusedSeries) != 0 {
		t.Fatalf("after the prune: %d series, refused %+v; want the new group stored", st.Series, st.RefusedSeries)
	}
	owners, _ := db.Owners()
	if len(owners) != 1 || owners[0].Series != 2 {
		t.Fatalf("owners = %+v", owners)
	}
}

func TestOpenOrResetMovesAnUnusableFileAside(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := map[string]func(t *testing.T, path string){
		"schema from the future": func(t *testing.T, path string) {
			db, err := Open(path, Options{})
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, db, t0, gauge("cp", "x", 1))
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(bucketMeta).Put(metaSchema, binary.BigEndian.AppendUint32(nil, schemaVersion+1))
			}); err != nil {
				t.Fatal(err)
			}
			db.Close()
		},
		"not a bbolt file": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(strings.Repeat("not a database ", 4096)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"damaged pages behind good meta pages": func(t *testing.T, path string) {
			db, err := Open(path, Options{})
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 50; i++ {
				mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), gauge("cp", "x", 1))
			}
			pageSize := db.bolt.Info().PageSize
			db.Close()
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for i := 2 * pageSize; i < len(raw); i++ {
				raw[i] = 0xFF
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metrics.db")
			spoil(t, path)
			db, rec, err := OpenOrReset(path, Options{}, now)
			if err != nil {
				t.Fatalf("OpenOrReset = %v", err)
			}
			defer db.Close()
			want := fmt.Sprintf("%s.unreadable-%d", path, now.Unix())
			if rec == nil || rec.MovedTo != want || rec.Cause == nil {
				t.Fatalf("recovery = %+v, want the file moved to %s", rec, want)
			}
			// bbolt panics on a damaged freelist; Open turns that into an error.
			if name == "damaged pages behind good meta pages" && !strings.Contains(rec.Cause.Error(), "is damaged") {
				t.Fatalf("cause = %v, want the recovered panic", rec.Cause)
			}
			if _, err := os.Stat(want); err != nil {
				t.Fatalf("the unusable file is not where it was moved: %v", err)
			}
			if st, _ := db.Stats(); st.Series != 0 {
				t.Fatalf("fresh store holds %d series", st.Series)
			}
			mustWrite(t, db, t0, gauge("cp", "x", 1))
		})
	}
}

func TestOpenOrResetLeavesAHeldFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	held, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	db, rec, err := OpenOrReset(path, Options{}, time.Now())
	if !errors.Is(err, ErrLocked) || db != nil || rec != nil {
		t.Fatalf("OpenOrReset on a held file = %v, %+v, %v; want ErrLocked and nothing moved", db, rec, err)
	}
	if matches, _ := filepath.Glob(path + ".unreadable-*"); len(matches) != 0 {
		t.Fatalf("a held file was moved aside: %v", matches)
	}
	// A missing directory is reported, not "recovered".
	if _, rec, err := OpenOrReset(filepath.Join(t.TempDir(), "gone", "metrics.db"), Options{}, time.Now()); err == nil || rec != nil {
		t.Fatalf("OpenOrReset in a missing directory = %+v, %v", rec, err)
	}
}

// TestAppendedRowsFillTheirPages checks the tier buckets' fill percent with
// a production-shaped fleet: rows arrive at the end of each owner's range,
// so pages split near full stay fuller. Measured over these 1000 minutes,
// the 1m tier's leaf pages are 73 percent full at the 0.95 fill percent and
// 49 percent at bbolt's default of one half.
func TestAppendedRowsFillTheirPages(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	db.bolt.NoSync = true
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		c.Set(at)
		mustWrite(t, db, at, realisticFleetBatch(rng)...)
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		bs := tx.Bucket([]byte(tierPrefix + "1m")).Stats()
		if bs.LeafPageN < 10 {
			t.Fatalf("only %d leaf pages; the check needs more", bs.LeafPageN)
		}
		if fill := float64(bs.LeafInuse) / float64(bs.LeafAlloc); fill < 0.65 {
			t.Fatalf("1m leaf pages are %.0f%% full, want at least 65%%", fill*100)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRestartKeepsTheHorizon: the horizon is stored with the data, so a
// restart in the middle of a clock fault does not hand the next write an
// unbounded trim.
func TestRestartKeepsTheHorizon(t *testing.T) {
	c := &clock{t: t0}
	path := filepath.Join(t.TempDir(), "metrics.db")
	db, err := Open(path, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), gauge("cp", "x", 1))
	}
	db.Close()
	db, err = Open(path, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustWrite(t, db, t0.Add(365*24*time.Hour), gauge("cp", "x", 2))
	if got := rowsFor(t, db, "cp", "1m"); got < 120 {
		t.Fatalf("1m rows after a restart and a clock a year ahead = %d, want the 120 real minutes kept", got)
	}
}
