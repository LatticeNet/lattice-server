// Package metricsdb is the control plane's embedded, bounded time-series
// store (metrics.db): its own process and host, its stores, its HTTP route
// groups and plugin calls, and the node metrics agents send on every beat,
// kept long enough to answer "has this been creeping up for a month".
//
// It is a separate bbolt file beside state.json, so recording a point never
// rewrites state.json and never touches the hot store. bbolt rather than the
// SQLite trace.db uses because every read here is a key range: one owner's
// buckets between two instants. There is no relational query to serve.
//
// # Shape
//
// A series is (owner, name): owner "node/<id>" holds that node's cpu, memory,
// disk, load, network and beat gap; owner "cp" holds the process and host;
// "cp.http" one series per route group; "plugin/<id>" one per method. A
// point is one bucket of one series: a Gauge (count, min, max, sum) or an
// Event (count, failures, summed, smallest and largest duration, and a
// latency histogram).
//
// Each tier is one bbolt bucket keyed by owner id and bucket start, and one
// value holds every point that owner has in that bucket. So one flush writes
// one row per owner (about 45 rows for a 34-node fleet) instead of one per
// series, deleting a node is a key range per tier, and a node page's chart
// is one range scan.
//
// # Tiers
//
// Every tier has a fixed resolution and a fixed retention (DefaultTiers):
//
//	1 min for 48 h    what happened last night, minute by minute
//	5 min for 14 d    this week against last week
//	1 h   for 90 d    a month or a quarter, hour by hour
//	1 d   for 1830 d  five years, one point a day
//
// A series therefore holds at most 2880 + 4032 + 2160 + 1830 = 10,902
// points whatever happens, and the file is bounded by the number of series
// times that. The number of series is capped (Options.MaxSeries, and per
// owner Options.MaxSeriesPerOwner); a series first seen past a cap is not
// stored and is counted in Stats.DroppedSeries, so the cap is visible rather
// than silent.
//
// Only the finest tier is written from outside. A coarser bucket is rolled up
// from the tier below once it closes, inside the same transaction as the
// write that closed it, and the last rolled bucket of each tier is recorded
// beside the data. A server that was down catches up from whatever the finer
// tier still holds on its next write, so a restart loses at most the minute
// that was being collected in memory.
//
// bbolt reuses the pages that retention and deletion free but never shrinks
// the file, so the file grows to its steady-state size and stays there.
package metricsdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Tier is one fixed resolution kept for a fixed time.
type Tier struct {
	Name string
	Res  time.Duration
	Keep time.Duration
}

// Slots is the most buckets one series can hold in this tier.
func (t Tier) Slots() int { return int(t.Keep / t.Res) }

// DefaultTiers is the production retention; the package comment says why.
var DefaultTiers = []Tier{
	{Name: "1m", Res: time.Minute, Keep: 48 * time.Hour},
	{Name: "5m", Res: 5 * time.Minute, Keep: 14 * 24 * time.Hour},
	{Name: "1h", Res: time.Hour, Keep: 90 * 24 * time.Hour},
	{Name: "1d", Res: 24 * time.Hour, Keep: 1830 * 24 * time.Hour},
}

const (
	// DefaultMaxSeries fits the control plane's own series (about 130) plus
	// seven per node for a fleet of about 120 nodes.
	DefaultMaxSeries = 1024
	// DefaultMaxSeriesPerOwner bounds one owner: the route groups, a
	// plugin's methods, the store's callers.
	DefaultMaxSeriesPerOwner = 256
	// maxNameBytes bounds an owner or series name.
	maxNameBytes = 200
)

// Options configures a DB. A zero value takes every default.
type Options struct {
	Tiers             []Tier
	MaxSeries         int
	MaxSeriesPerOwner int
	// Now is the clock reads measure retention against. Nil is time.Now.
	Now func() time.Time
}

func (o Options) withDefaults() (Options, error) {
	if len(o.Tiers) == 0 {
		o.Tiers = DefaultTiers
	}
	for i, t := range o.Tiers {
		if t.Name == "" || t.Res <= 0 || t.Keep < t.Res || t.Res%time.Second != 0 {
			return o, fmt.Errorf("metricsdb: tier %d (%q) is not a whole-second resolution kept at least one bucket", i, t.Name)
		}
		if i > 0 {
			prev := o.Tiers[i-1]
			if t.Res <= prev.Res || t.Res%prev.Res != 0 || t.Keep < prev.Keep {
				return o, fmt.Errorf("metricsdb: tier %q must be a coarser multiple of %q kept at least as long", t.Name, prev.Name)
			}
		}
	}
	if o.MaxSeries <= 0 {
		o.MaxSeries = DefaultMaxSeries
	}
	if o.MaxSeriesPerOwner <= 0 {
		o.MaxSeriesPerOwner = DefaultMaxSeriesPerOwner
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o, nil
}

var (
	bucketMeta   = []byte("meta")
	bucketOwners = []byte("owners")
	bucketSeries = []byte("series")
	tierPrefix   = "tier/"
	metaSchema   = []byte("schema")
	rolledPrefix = "rolled/"
)

const schemaVersion = 1

// ErrClosed is returned by a DB that has been closed.
var ErrClosed = errors.New("metricsdb: closed")

type seriesKey struct {
	owner uint32
	name  string
}

type seriesMeta struct {
	id   uint32
	kind Kind
}

type seriesRef struct {
	owner uint32
	name  string
	kind  Kind
}

// DB is the metrics store. It is safe for concurrent use: one writer at a
// time, readers concurrent with it.
type DB struct {
	path  string
	bolt  *bolt.DB
	opts  Options
	tiers []Tier

	// writeMu serializes everything that writes, so the catalog below
	// changes only from one goroutine at a time and only after a commit.
	writeMu sync.Mutex

	mu          sync.RWMutex
	closed      bool
	owners      map[string]uint32
	ownerNames  map[uint32]string
	series      map[seriesKey]seriesMeta
	seriesRefs  map[uint32]seriesRef
	ownerCounts map[uint32]int
	nextOwner   uint32
	nextSeries  uint32
	rolled      []int64 // per tier, unix start of the last rolled bucket; 0 none
	dropped     uint64
	lastWrite   WriteResult
	statsCache  *Stats
	statsAt     time.Time
}

// Open opens or creates the store at path.
func Open(path string, opts Options) (*DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("metricsdb: path is required")
	}
	opts, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	bdb, err := bolt.Open(path, 0o600, &bolt.Options{
		Timeout: 2 * time.Second,
		// The hash-map freelist allocates in constant time however many
		// pages retention has freed.
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		return nil, fmt.Errorf("metricsdb: open %s: %w", path, err)
	}
	db := &DB{
		path:        path,
		bolt:        bdb,
		opts:        opts,
		tiers:       opts.Tiers,
		owners:      map[string]uint32{},
		ownerNames:  map[uint32]string{},
		series:      map[seriesKey]seriesMeta{},
		seriesRefs:  map[uint32]seriesRef{},
		ownerCounts: map[uint32]int{},
		rolled:      make([]int64, len(opts.Tiers)),
	}
	if err := db.init(); err != nil {
		bdb.Close()
		return nil, err
	}
	return db, nil
}

// init creates the buckets, drops the buckets of tiers no longer configured
// (so a retention change cannot leave an unbounded orphan behind), and loads
// the catalog.
func (db *DB) init() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		if v := meta.Get(metaSchema); v != nil {
			if got := binary.BigEndian.Uint32(v); got != schemaVersion {
				return fmt.Errorf("metricsdb: schema %d not understood (want %d)", got, schemaVersion)
			}
		} else if err := meta.Put(metaSchema, binary.BigEndian.AppendUint32(nil, schemaVersion)); err != nil {
			return err
		}
		owners, err := tx.CreateBucketIfNotExists(bucketOwners)
		if err != nil {
			return err
		}
		series, err := tx.CreateBucketIfNotExists(bucketSeries)
		if err != nil {
			return err
		}
		configured := map[string]bool{}
		for _, t := range db.tiers {
			configured[tierPrefix+t.Name] = true
			if _, err := tx.CreateBucketIfNotExists([]byte(tierPrefix + t.Name)); err != nil {
				return err
			}
		}
		var stale [][]byte
		if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if strings.HasPrefix(string(name), tierPrefix) && !configured[string(name)] {
				stale = append(stale, append([]byte(nil), name...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, name := range stale {
			if err := tx.DeleteBucket(name); err != nil {
				return err
			}
			_ = meta.Delete([]byte(rolledPrefix + strings.TrimPrefix(string(name), tierPrefix)))
		}
		if err := owners.ForEach(func(k, v []byte) error {
			if len(v) != 4 {
				return fmt.Errorf("metricsdb: owner %q has a malformed id", k)
			}
			id := binary.BigEndian.Uint32(v)
			db.owners[string(k)] = id
			db.ownerNames[id] = string(k)
			db.nextOwner = max(db.nextOwner, id)
			return nil
		}); err != nil {
			return err
		}
		if err := series.ForEach(func(k, v []byte) error {
			if len(k) < 4 || len(v) != 5 {
				return fmt.Errorf("metricsdb: series %q is malformed", k)
			}
			owner := binary.BigEndian.Uint32(k[:4])
			name := string(k[4:])
			id := binary.BigEndian.Uint32(v[:4])
			kind := Kind(v[4])
			db.series[seriesKey{owner, name}] = seriesMeta{id: id, kind: kind}
			db.seriesRefs[id] = seriesRef{owner: owner, name: name, kind: kind}
			db.ownerCounts[owner]++
			db.nextSeries = max(db.nextSeries, id)
			return nil
		}); err != nil {
			return err
		}
		for i, t := range db.tiers {
			if v := meta.Get([]byte(rolledPrefix + t.Name)); len(v) == 8 {
				db.rolled[i] = int64(binary.BigEndian.Uint64(v))
			}
		}
		return nil
	})
}

// Close closes the file. Writes after Close fail with ErrClosed.
func (db *DB) Close() error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		return nil
	}
	db.closed = true
	db.mu.Unlock()
	return db.bolt.Close()
}

func (db *DB) now() time.Time { return db.opts.Now() }

// Path is the file the store lives in.
func (db *DB) Path() string { return db.path }

// Tiers returns the configured tiers, finest first.
func (db *DB) Tiers() []Tier { return append([]Tier(nil), db.tiers...) }

// Sample is one series' point for the bucket being written.
type Sample struct {
	Owner string
	Name  string
	Kind  Kind
	Gauge Gauge
	Event *Event
}

func (s Sample) point() Point {
	return Point{Kind: s.Kind, Gauge: s.Gauge, Event: s.Event}
}

// WriteResult reports one Write.
type WriteResult struct {
	At       time.Time     `json:"at"`
	Points   int           `json:"points"`
	Rows     int           `json:"rows"`
	Dropped  int           `json:"dropped"`
	Rolled   int           `json:"rolled"`
	Trimmed  int           `json:"trimmed"`
	Duration time.Duration `json:"duration"`
}

func ownerKey(owner uint32, unix int64) []byte {
	k := make([]byte, 12)
	binary.BigEndian.PutUint32(k[:4], owner)
	binary.BigEndian.PutUint64(k[4:], uint64(unix))
	return k
}

func ownerPrefix(owner uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, owner)
}

func floorUnix(unix int64, res time.Duration) int64 {
	step := int64(res / time.Second)
	q := unix / step
	if unix%step < 0 {
		q--
	}
	return q * step
}

func validName(s string) bool {
	return s != "" && len(s) <= maxNameBytes && !strings.ContainsRune(s, 0)
}

// staged holds catalog entries a transaction created, applied to the
// in-memory catalog only once it commits.
type staged struct {
	owners      map[string]uint32
	series      map[seriesKey]seriesMeta
	ownerCounts map[uint32]int
	nextOwner   uint32
	nextSeries  uint32
	total       int
}

// Write records samples into the finest tier's bucket that contains at, in one
// transaction, then rolls up every coarser bucket that has closed and trims
// what has aged out. A bucket written again is merged with what it holds, so
// a final flush at shutdown and the first flush after the restart add up. A
// sample whose series is new past a cardinality cap is dropped and counted.
func (db *DB) Write(at time.Time, samples []Sample) (WriteResult, error) {
	start := time.Now()
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	db.mu.RLock()
	closed := db.closed
	db.mu.RUnlock()
	if closed {
		return WriteResult{}, ErrClosed
	}
	fine := db.tiers[0]
	minute := floorUnix(at.Unix(), fine.Res)
	res := WriteResult{At: time.Unix(minute, 0).UTC()}

	st := &staged{
		owners:      map[string]uint32{},
		series:      map[seriesKey]seriesMeta{},
		ownerCounts: map[uint32]int{},
	}
	db.mu.RLock()
	st.nextOwner, st.nextSeries = db.nextOwner, db.nextSeries
	st.total = len(db.series)
	db.mu.RUnlock()

	var rolledAfter []int64
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		byOwner := map[uint32]map[uint32]Point{}
		for _, s := range samples {
			if !s.Kind.valid() || !validName(s.Owner) || !validName(s.Name) {
				res.Dropped++
				continue
			}
			p := s.point()
			if p.empty() {
				continue
			}
			ownerID, seriesID, ok, err := db.resolve(tx, st, s.Owner, s.Name, s.Kind)
			if err != nil {
				return err
			}
			if !ok {
				res.Dropped++
				continue
			}
			pts := byOwner[ownerID]
			if pts == nil {
				pts = map[uint32]Point{}
				byOwner[ownerID] = pts
			}
			cur := pts[seriesID]
			cur.Merge(p)
			pts[seriesID] = cur
			res.Points++
		}
		// The newest minute stored before this write, read before it lands:
		// the trim below may not run further ahead of it than one step.
		prevNewest, havePrev := newestRowTx(tx, fine, db.ownerIDsWith(st))
		fb := tierBucket(tx, fine)
		for ownerID, pts := range byOwner {
			key := ownerKey(ownerID, minute)
			if existing := fb.Get(key); existing != nil {
				if err := decodeRow(existing, nil, func(series uint32, p Point) {
					cur := pts[series]
					cur.Merge(p)
					pts[series] = cur
				}); err != nil {
					return err
				}
			}
			if err := fb.Put(key, encodeRow(sortedPoints(pts))); err != nil {
				return err
			}
			res.Rows++
		}
		ownerIDs := db.ownerIDsWith(st)
		rolled, n, err := db.rollTx(tx, ownerIDs, minute)
		if err != nil {
			return err
		}
		res.Rolled = n
		rolledAfter = rolled
		trimHorizon := minute + int64(fine.Res/time.Second)
		if havePrev && trimHorizon > prevNewest+maxTrimAdvance {
			trimHorizon = prevNewest + maxTrimAdvance
		}
		trimmed, err := db.trimTx(tx, ownerIDs, trimHorizon)
		if err != nil {
			return err
		}
		res.Trimmed = trimmed
		return nil
	})
	if err != nil {
		return WriteResult{}, err
	}
	res.Duration = time.Since(start)
	db.mu.Lock()
	for name, id := range st.owners {
		db.owners[name] = id
		db.ownerNames[id] = name
	}
	for k, meta := range st.series {
		db.series[k] = meta
		db.seriesRefs[meta.id] = seriesRef{owner: k.owner, name: k.name, kind: meta.kind}
	}
	for owner, n := range st.ownerCounts {
		db.ownerCounts[owner] += n
	}
	db.nextOwner, db.nextSeries = st.nextOwner, st.nextSeries
	copy(db.rolled, rolledAfter)
	db.dropped += uint64(res.Dropped)
	db.lastWrite = res
	db.mu.Unlock()
	return res, nil
}

func sortedPoints(pts map[uint32]Point) []rowPoint {
	out := make([]rowPoint, 0, len(pts))
	for id, p := range pts {
		out = append(out, rowPoint{series: id, point: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].series < out[j].series })
	return out
}

// resolve finds or creates the ids for (owner, name), honouring the caps.
// Creation is written into tx and staged for the in-memory catalog.
func (db *DB) resolve(tx *bolt.Tx, st *staged, owner, name string, kind Kind) (uint32, uint32, bool, error) {
	db.mu.RLock()
	ownerID, ownerKnown := db.owners[owner]
	var meta seriesMeta
	var seriesKnown bool
	ownerCount := 0
	if ownerKnown {
		meta, seriesKnown = db.series[seriesKey{ownerID, name}]
		ownerCount = db.ownerCounts[ownerID]
	}
	db.mu.RUnlock()
	if !ownerKnown {
		ownerID, ownerKnown = st.owners[owner]
	}
	if ownerKnown && !seriesKnown {
		meta, seriesKnown = st.series[seriesKey{ownerID, name}]
	}
	if seriesKnown {
		return ownerID, meta.id, meta.kind == kind, nil
	}
	ownerCount += st.ownerCounts[ownerID]
	if st.total >= db.opts.MaxSeries || ownerCount >= db.opts.MaxSeriesPerOwner {
		return 0, 0, false, nil
	}
	if !ownerKnown {
		st.nextOwner++
		ownerID = st.nextOwner
		if err := tx.Bucket(bucketOwners).Put([]byte(owner), binary.BigEndian.AppendUint32(nil, ownerID)); err != nil {
			return 0, 0, false, err
		}
		st.owners[owner] = ownerID
	}
	st.nextSeries++
	id := st.nextSeries
	key := append(ownerPrefix(ownerID), name...)
	val := append(binary.BigEndian.AppendUint32(nil, id), byte(kind))
	if err := tx.Bucket(bucketSeries).Put(key, val); err != nil {
		return 0, 0, false, err
	}
	st.series[seriesKey{ownerID, name}] = seriesMeta{id: id, kind: kind}
	st.ownerCounts[ownerID]++
	st.total++
	return ownerID, id, true, nil
}

func (db *DB) ownerIDsWith(st *staged) []uint32 {
	db.mu.RLock()
	ids := make([]uint32, 0, len(db.ownerNames)+len(st.owners))
	for id := range db.ownerNames {
		ids = append(ids, id)
	}
	db.mu.RUnlock()
	for _, id := range st.owners {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// rollTx rolls every coarser tier up to the end of the finest bucket just
// written, and re-rolls the coarser buckets containing it when they had
// already been rolled (a write that landed late). It returns the new last
// rolled bucket per tier and how many buckets it rolled.
func (db *DB) rollTx(tx *bolt.Tx, owners []uint32, written int64) ([]int64, int, error) {
	db.mu.RLock()
	rolled := append([]int64(nil), db.rolled...)
	db.mu.RUnlock()
	horizon := written + int64(db.tiers[0].Res/time.Second)
	meta := tx.Bucket(bucketMeta)
	count := 0
	for i := 1; i < len(db.tiers); i++ {
		t := db.tiers[i]
		step := int64(t.Res / time.Second)
		finer := db.tiers[i-1]
		// A late write into a bucket already rolled: roll it again.
		if s := floorUnix(written, t.Res); rolled[i] != 0 && s <= rolled[i] {
			if err := db.rollBucket(tx, owners, finer, t, s); err != nil {
				return nil, 0, err
			}
			count++
		}
		// Catch up every bucket that has closed since the last roll, starting
		// no earlier than the oldest row the finer tier still holds: a server
		// that was down a year rolls what survived, not a year of empties.
		closedEnd := floorUnix(horizon, t.Res)
		last := rolled[i]
		oldest, any := oldestRowTx(tx, finer, owners)
		if !any {
			// Nothing below to roll: the closed buckets are all empty.
			if closedEnd-step > last {
				last = closedEnd - step
			}
		} else {
			first := floorUnix(oldest, t.Res)
			if rolled[i] != 0 && rolled[i]+step > first {
				first = rolled[i] + step
			}
			for s := first; s+step <= horizon; s += step {
				if err := db.rollBucket(tx, owners, finer, t, s); err != nil {
					return nil, 0, err
				}
				last = s
				count++
			}
		}
		if last != rolled[i] {
			rolled[i] = last
			if err := meta.Put([]byte(rolledPrefix+t.Name), binary.BigEndian.AppendUint64(nil, uint64(last))); err != nil {
				return nil, 0, err
			}
		}
	}
	return rolled, count, nil
}

// maxTrimAdvance bounds how far one write may move the retention line past
// the newest minute already stored, in seconds. Retention is measured from
// the minute being written, so without it a clock stepped a year ahead for
// one flush would trim every finer tier against that future and erase weeks
// of history the moment the clock came back. With it, a server that really
// was down for days catches its trimming up an hour per flush.
const maxTrimAdvance = int64(3600)

// newestRowTx returns the start of the newest row any of owners has in tier
// t, and false when none has one.
func newestRowTx(tx *bolt.Tx, t Tier, owners []uint32) (int64, bool) {
	c := tx.Bucket([]byte(tierPrefix + t.Name)).Cursor()
	var newest int64
	found := false
	for _, owner := range owners {
		var k []byte
		if next := owner + 1; next != 0 {
			if k, _ = c.Seek(ownerPrefix(next)); k == nil {
				k, _ = c.Last()
			} else {
				k, _ = c.Prev()
			}
		} else {
			k, _ = c.Last()
		}
		if len(k) != 12 || binary.BigEndian.Uint32(k[:4]) != owner {
			continue
		}
		if at := int64(binary.BigEndian.Uint64(k[4:])); !found || at > newest {
			newest, found = at, true
		}
	}
	return newest, found
}

// appendFill is the fill percent for the tier buckets. Rows arrive in time
// order at the end of each owner's key range, so splitting a full page at
// bbolt's default of half would leave every page half empty for good.
const appendFill = 0.95

func tierBucket(tx *bolt.Tx, t Tier) *bolt.Bucket {
	b := tx.Bucket([]byte(tierPrefix + t.Name))
	b.FillPercent = appendFill
	return b
}

// oldestRowTx returns the start of the oldest row any of owners has in tier
// t, and false when none has one.
func oldestRowTx(tx *bolt.Tx, t Tier, owners []uint32) (int64, bool) {
	c := tx.Bucket([]byte(tierPrefix + t.Name)).Cursor()
	var oldest int64
	found := false
	for _, owner := range owners {
		prefix := ownerPrefix(owner)
		k, _ := c.Seek(prefix)
		if len(k) != 12 || string(k[:4]) != string(prefix) {
			continue
		}
		at := int64(binary.BigEndian.Uint64(k[4:]))
		if !found || at < oldest {
			oldest, found = at, true
		}
	}
	return oldest, found
}

// rollBucket rebuilds every owner's row in coarse bucket s from the finer
// tier. It is a pure function of the finer rows, so rolling twice is safe.
func (db *DB) rollBucket(tx *bolt.Tx, owners []uint32, finer, coarse Tier, s int64) error {
	fb := tx.Bucket([]byte(tierPrefix + finer.Name))
	cb := tierBucket(tx, coarse)
	end := s + int64(coarse.Res/time.Second)
	for _, owner := range owners {
		pts := map[uint32]Point{}
		c := fb.Cursor()
		lo, hi := ownerKey(owner, s), ownerKey(owner, end)
		for k, v := c.Seek(lo); k != nil && string(k) < string(hi); k, v = c.Next() {
			if err := decodeRow(v, nil, func(series uint32, p Point) {
				cur := pts[series]
				cur.Merge(p)
				pts[series] = cur
			}); err != nil {
				return err
			}
		}
		key := ownerKey(owner, s)
		if len(pts) == 0 {
			if cb.Get(key) != nil {
				if err := cb.Delete(key); err != nil {
					return err
				}
			}
			continue
		}
		if err := cb.Put(key, encodeRow(sortedPoints(pts))); err != nil {
			return err
		}
	}
	return nil
}

// trimTx deletes, per tier and owner, the buckets that ended before the
// tier's retention line measured back from horizon.
func (db *DB) trimTx(tx *bolt.Tx, owners []uint32, horizon int64) (int, error) {
	n := 0
	for _, t := range db.tiers {
		b := tierBucket(tx, t)
		cutoff := horizon - int64(t.Keep/time.Second)
		for _, owner := range owners {
			c := b.Cursor()
			hi := ownerKey(owner, cutoff)
			prefix := ownerPrefix(owner)
			for k, _ := c.Seek(prefix); k != nil && len(k) == 12 && string(k[:4]) == string(prefix) && string(k) < string(hi); k, _ = c.Seek(prefix) {
				if err := b.Delete(k); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}

// DeleteOwner removes an owner and every point and series it has, in every
// tier. It reports how many series went. An unknown owner is not an error.
func (db *DB) DeleteOwner(owner string) (int, error) {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	db.mu.RLock()
	closed := db.closed
	id, ok := db.owners[owner]
	db.mu.RUnlock()
	if closed {
		return 0, ErrClosed
	}
	if !ok {
		return 0, nil
	}
	removed := 0
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		prefix := ownerPrefix(id)
		buckets := [][]byte{bucketSeries}
		for _, t := range db.tiers {
			buckets = append(buckets, []byte(tierPrefix+t.Name))
		}
		for _, name := range buckets {
			b := tx.Bucket(name)
			c := b.Cursor()
			for k, _ := c.Seek(prefix); k != nil && len(k) >= 4 && string(k[:4]) == string(prefix); k, _ = c.Seek(prefix) {
				if err := b.Delete(k); err != nil {
					return err
				}
				if string(name) == string(bucketSeries) {
					removed++
				}
			}
		}
		return tx.Bucket(bucketOwners).Delete([]byte(owner))
	})
	if err != nil {
		return 0, err
	}
	db.mu.Lock()
	delete(db.owners, owner)
	delete(db.ownerNames, id)
	delete(db.ownerCounts, id)
	for k, meta := range db.series {
		if k.owner == id {
			delete(db.series, k)
			delete(db.seriesRefs, meta.id)
		}
	}
	db.statsCache = nil
	db.mu.Unlock()
	return removed, nil
}

// OwnerInfo describes one owner.
type OwnerInfo struct {
	Owner  string    `json:"owner"`
	Series int       `json:"series"`
	Newest time.Time `json:"newest,omitzero"`
}

// Owners lists every owner with its series count and its newest bucket in
// any tier, sorted by name.
func (db *DB) Owners() ([]OwnerInfo, error) {
	db.mu.RLock()
	if db.closed {
		db.mu.RUnlock()
		return nil, ErrClosed
	}
	out := make([]OwnerInfo, 0, len(db.owners))
	ids := map[string]uint32{}
	for name, id := range db.owners {
		out = append(out, OwnerInfo{Owner: name, Series: db.ownerCounts[id]})
		ids[name] = id
	}
	db.mu.RUnlock()
	err := db.bolt.View(func(tx *bolt.Tx) error {
		for i := range out {
			out[i].Newest = db.newestTx(tx, ids[out[i].Owner])
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Owner < out[j].Owner })
	return out, err
}

func (db *DB) newestTx(tx *bolt.Tx, owner uint32) time.Time {
	var newest int64
	for _, t := range db.tiers {
		if at, ok := newestRowTx(tx, t, []uint32{owner}); ok {
			newest = max(newest, at)
		}
	}
	if newest == 0 {
		return time.Time{}
	}
	return time.Unix(newest, 0).UTC()
}

// PruneOwners deletes every owner for which drop returns true, given the
// owner's name and its newest bucket. It returns the owners it deleted.
func (db *DB) PruneOwners(drop func(owner string, newest time.Time) bool) ([]string, error) {
	owners, err := db.Owners()
	if err != nil {
		return nil, err
	}
	var gone []string
	for _, o := range owners {
		if !drop(o.Owner, o.Newest) {
			continue
		}
		if _, err := db.DeleteOwner(o.Owner); err != nil {
			return gone, err
		}
		gone = append(gone, o.Owner)
	}
	return gone, nil
}

// TierStats describes one tier.
type TierStats struct {
	Name              string `json:"name"`
	ResolutionSeconds int64  `json:"resolution_seconds"`
	RetentionSeconds  int64  `json:"retention_seconds"`
	SlotsPerSeries    int    `json:"slots_per_series"`
	Rows              int    `json:"rows"`
	LastRolled        int64  `json:"last_rolled,omitempty"`
}

// Stats is the store's account of itself.
type Stats struct {
	Path              string      `json:"path"`
	SizeBytes         int64       `json:"size_bytes"`
	Series            int         `json:"series"`
	MaxSeries         int         `json:"max_series"`
	MaxSeriesPerOwner int         `json:"max_series_per_owner"`
	Owners            int         `json:"owners"`
	DroppedSeries     uint64      `json:"dropped_series"`
	SlotsPerSeries    int         `json:"slots_per_series"`
	Tiers             []TierStats `json:"tiers"`
	LastWrite         WriteResult `json:"last_write"`
}

// statsTTL bounds how often Stats walks the tier buckets to count rows.
const statsTTL = time.Minute

// Stats reports the file size, the catalog and the tiers. Row counts walk the
// tier buckets, so they are cached for a minute.
func (db *DB) Stats() (Stats, error) {
	db.mu.RLock()
	if db.closed {
		db.mu.RUnlock()
		return Stats{}, ErrClosed
	}
	cached, cachedAt := db.statsCache, db.statsAt
	st := Stats{
		Path:              db.path,
		Series:            len(db.series),
		MaxSeries:         db.opts.MaxSeries,
		MaxSeriesPerOwner: db.opts.MaxSeriesPerOwner,
		Owners:            len(db.owners),
		DroppedSeries:     db.dropped,
		LastWrite:         db.lastWrite,
	}
	rolled := append([]int64(nil), db.rolled...)
	db.mu.RUnlock()
	if fi, err := os.Stat(db.path); err == nil {
		st.SizeBytes = fi.Size()
	}
	for i, t := range db.tiers {
		st.SlotsPerSeries += t.Slots()
		st.Tiers = append(st.Tiers, TierStats{
			Name:              t.Name,
			ResolutionSeconds: int64(t.Res / time.Second),
			RetentionSeconds:  int64(t.Keep / time.Second),
			SlotsPerSeries:    t.Slots(),
			LastRolled:        rolled[i],
		})
	}
	if cached != nil && time.Since(cachedAt) < statsTTL {
		for i := range st.Tiers {
			if i < len(cached.Tiers) {
				st.Tiers[i].Rows = cached.Tiers[i].Rows
			}
		}
		return st, nil
	}
	err := db.bolt.View(func(tx *bolt.Tx) error {
		for i, t := range db.tiers {
			st.Tiers[i].Rows = tx.Bucket([]byte(tierPrefix + t.Name)).Stats().KeyN
		}
		return nil
	})
	if err != nil {
		return Stats{}, err
	}
	db.mu.Lock()
	snapshot := st
	db.statsCache, db.statsAt = &snapshot, time.Now()
	db.mu.Unlock()
	return st, nil
}
