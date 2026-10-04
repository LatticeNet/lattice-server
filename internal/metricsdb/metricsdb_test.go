package metricsdb

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
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

func TestAClockStepAheadDoesNotEraseHistory(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	for i := 0; i < 70; i++ {
		mustWrite(t, db, t0.Add(time.Duration(i)*time.Minute), gauge("cp", "x", 1))
	}
	// One flush with the clock a year ahead, then the clock comes back.
	ahead := t0.Add(365 * 24 * time.Hour)
	mustWrite(t, db, ahead, gauge("cp", "x", 2))
	mustWrite(t, db, t0.Add(71*time.Minute), gauge("cp", "x", 3))
	c.Set(t0.Add(72 * time.Minute))
	if got := rowsFor(t, db, "cp", "1m"); got < 70 {
		t.Fatalf("1m rows after a clock step = %d, want the 70 real minutes kept", got)
	}
	if got := rowsFor(t, db, "cp", "5m"); got < 14 {
		t.Fatalf("5m rows after a clock step = %d, want 14", got)
	}
	if got := rowsFor(t, db, "cp", "1h"); got < 1 {
		t.Fatalf("1h rows after a clock step = %d", got)
	}
}

func TestTrimmingCatchesUpAfterDowntime(t *testing.T) {
	db, c, _ := openTest(t, Options{})
	mustWrite(t, db, t0, gauge("cp", "x", 1))
	// Back three days later with a correct clock: the old minute is past
	// the 48-hour retention but the trim line moves an hour per write.
	later := t0.Add(72 * time.Hour)
	c.Set(later)
	mustWrite(t, db, later, gauge("cp", "x", 2))
	if got := rowsFor(t, db, "cp", "1m"); got != 2 {
		t.Fatalf("first write after downtime: 1m rows = %d, want 2 (trim held back)", got)
	}
	for i := 1; i <= 30; i++ {
		mustWrite(t, db, later.Add(time.Duration(i)*time.Minute), gauge("cp", "x", 3))
	}
	if got := rowsFor(t, db, "cp", "1m"); got != 31 {
		t.Fatalf("after catching up: 1m rows = %d, want only the 31 recent minutes", got)
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
	if res.Dropped != 2 || res.Points != 5 {
		t.Fatalf("write = %+v, want 5 points and 2 dropped", res)
	}
	st, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Series != 5 || st.DroppedSeries != 2 {
		t.Fatalf("stats = %+v", st)
	}
	// A known series keeps writing at the cap; a new one still drops.
	res = mustWrite(t, db, t0.Add(time.Minute), gauge("node/a", "m0", 2), gauge("node/c", "m0", 2))
	if res.Points != 1 || res.Dropped != 1 {
		t.Fatalf("second write = %+v, want the known series kept and the new one dropped", res)
	}
	// Deleting an owner frees its share of the cap.
	if n, err := db.DeleteOwner("node/a"); err != nil || n != 3 {
		t.Fatalf("delete = %d, %v", n, err)
	}
	res = mustWrite(t, db, t0.Add(2*time.Minute), gauge("node/c", "m0", 3))
	if res.Points != 1 || res.Dropped != 0 {
		t.Fatalf("write after delete = %+v", res)
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
	db, _, _ := openTest(t, Options{})
	res := mustWrite(t, db, t0, gauge("", "x", 1), gauge("cp", "bad\x00name", 1), Sample{Owner: "cp", Name: "k", Kind: 9})
	if res.Dropped != 3 || res.Points != 0 {
		t.Fatalf("write = %+v, want all three dropped", res)
	}
	// One name, two kinds: the second kind is refused.
	mustWrite(t, db, t0, gauge("cp", "same", 1))
	res = mustWrite(t, db, t0.Add(time.Minute), event("cp", "same", 0, time.Millisecond))
	if res.Dropped != 1 {
		t.Fatalf("kind change = %+v, want dropped", res)
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
