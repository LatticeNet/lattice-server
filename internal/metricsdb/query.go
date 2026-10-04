package metricsdb

import (
	"encoding/binary"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// DefaultMaxPoints is how many buckets a query returns per series when the
// caller does not say; MaxPoints is the most it may ask for.
const (
	DefaultMaxPoints = 360
	MaxPoints        = 2000
)

// TimedPoint is one bucket of a query result.
type TimedPoint struct {
	At time.Time
	Point
}

// SeriesPoints is one series of a query result, oldest bucket first. A
// bucket nothing was recorded in is absent, so a gap reads as a gap.
type SeriesPoints struct {
	Name   string
	Kind   Kind
	Points []TimedPoint
}

// QueryResult is what Query read and at which resolution.
type QueryResult struct {
	Owner string
	// Tier is the tier the points came from. Step is the width of each
	// returned bucket: the tier's resolution, or a multiple of it when the
	// range held more buckets than were asked for.
	Tier Tier
	Step time.Duration
	From time.Time
	To   time.Time
	// RetainedFrom is the oldest instant the chosen tier still holds.
	RetainedFrom time.Time
	Series       []SeriesPoints
}

// readBudget is how many rows per point a query may read before it moves to
// a coarser tier. Reading finer and merging gives exact buckets (a 24-hour
// chart of 360 points is 1-minute rows merged four at a time, not 5-minute
// rows), and eight rows a point keeps the read under 3000 rows for the
// default 360 points.
const readBudget = 8

// pickTier chooses the finest tier that still holds from and has no more
// than readBudget rows per requested point over the range; when none does,
// or no tier reaches back that far, the coarsest tier.
func (db *DB) pickTier(now, from, to time.Time, maxPoints int) int {
	span := to.Sub(from)
	for i, t := range db.tiers {
		if from.Before(now.Add(-t.Keep)) {
			continue
		}
		if span/t.Res <= time.Duration(readBudget*maxPoints) {
			return i
		}
	}
	// Every tier coarser than one that holds from holds it too, so in both
	// remaining cases the answer is the coarsest.
	return len(db.tiers) - 1
}

func clampPoints(n int) int {
	if n <= 0 {
		return DefaultMaxPoints
	}
	return min(n, MaxPoints)
}

// Query returns an owner's series (all of them when names is empty) over
// [from, to) from the tier pickTier chooses, merged into buckets of Step so
// that no series has more than maxPoints. The newest part of the range that
// the chosen tier has not rolled up yet is read from the finest tier, so a
// 30-day chart reaches the current minute. An unknown owner or name yields
// no points, not an error.
func (db *DB) Query(owner string, names []string, from, to time.Time, maxPoints int) (QueryResult, error) {
	maxPoints = clampPoints(maxPoints)
	now := db.now()
	if to.After(now) {
		to = now
	}
	if !from.Before(to) {
		from = to.Add(-db.tiers[0].Res)
	}
	ti := db.pickTier(now, from, to, maxPoints)
	tier := db.tiers[ti]
	step := tier.Res
	if buckets := int64(to.Sub(from) / tier.Res); buckets > int64(maxPoints) {
		mult := (buckets + int64(maxPoints) - 1) / int64(maxPoints)
		step = time.Duration(mult) * tier.Res
	}
	res := QueryResult{
		Owner:        owner,
		Tier:         tier,
		Step:         step,
		From:         time.Unix(floorUnix(from.Unix(), step), 0).UTC(),
		To:           to.UTC(),
		RetainedFrom: now.Add(-tier.Keep).UTC(),
	}
	acc, err := db.collect(owner, names, ti, res.From, to, func(unix int64) int64 { return floorUnix(unix, step) })
	if err != nil || acc == nil {
		return res, err
	}
	for _, s := range acc.order {
		buckets := acc.points[s.id]
		sp := SeriesPoints{Name: s.name, Kind: s.kind}
		keys := make([]int64, 0, len(buckets))
		for k := range buckets {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, k := range keys {
			sp.Points = append(sp.Points, TimedPoint{At: time.Unix(k, 0).UTC(), Point: *buckets[k]})
		}
		res.Series = append(res.Series, sp)
	}
	return res, nil
}

// Aggregate merges each named series (all of the owner's when names is
// empty) over [from, to) into one point, read from the finest tier that still
// holds from, with the unrolled tail read from the finest tier. A series with
// nothing recorded in the range is absent.
func (db *DB) Aggregate(owner string, names []string, from, to time.Time) (map[string]Point, Tier, error) {
	now := db.now()
	if to.After(now) {
		to = now
	}
	ti := db.pickTier(now, from, from, 0)
	acc, err := db.collect(owner, names, ti, from, to, func(int64) int64 { return 0 })
	out := map[string]Point{}
	if err != nil || acc == nil {
		return out, db.tiers[ti], err
	}
	for _, s := range acc.order {
		if p := acc.points[s.id][0]; p != nil {
			out[s.name] = *p
		}
	}
	return out, db.tiers[ti], nil
}

type collectedSeries struct {
	id   uint32
	name string
	kind Kind
}

type collected struct {
	order  []collectedSeries
	points map[uint32]map[int64]*Point
}

// collect reads owner's wanted series over [from, to) from tier ti and, for
// the part tier ti has not rolled yet, from the finest tier, folding every
// row into bucket(rowStart).
func (db *DB) collect(owner string, names []string, ti int, from, to time.Time, bucket func(int64) int64) (*collected, error) {
	db.mu.RLock()
	if db.closed {
		db.mu.RUnlock()
		return nil, ErrClosed
	}
	ownerID, ok := db.owners[owner]
	if !ok {
		db.mu.RUnlock()
		return nil, nil
	}
	acc := &collected{points: map[uint32]map[int64]*Point{}}
	if len(names) == 0 {
		for k, meta := range db.series {
			if k.owner == ownerID {
				acc.order = append(acc.order, collectedSeries{id: meta.id, name: k.name, kind: meta.kind})
			}
		}
	} else {
		seen := map[string]bool{}
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			if meta, ok := db.series[seriesKey{ownerID, name}]; ok {
				acc.order = append(acc.order, collectedSeries{id: meta.id, name: name, kind: meta.kind})
			}
		}
	}
	rolledEnd := int64(0)
	if ti > 0 && db.rolled[ti] != 0 {
		rolledEnd = db.rolled[ti] + int64(db.tiers[ti].Res/time.Second)
	}
	db.mu.RUnlock()
	sort.Slice(acc.order, func(i, j int) bool { return acc.order[i].name < acc.order[j].name })
	if len(acc.order) == 0 {
		return acc, nil
	}
	wanted := map[uint32]bool{}
	for _, s := range acc.order {
		wanted[s.id] = true
		acc.points[s.id] = map[int64]*Point{}
	}
	want := func(series uint32) bool { return wanted[series] }
	fold := func(rowStart int64) func(series uint32, p Point) {
		b := bucket(rowStart)
		return func(series uint32, p Point) {
			cur := acc.points[series][b]
			if cur == nil {
				cur = &Point{Kind: p.Kind}
				acc.points[series][b] = cur
			}
			cur.Merge(p)
		}
	}
	scan := func(tx *bolt.Tx, t Tier, lo, hi int64) error {
		if lo >= hi {
			return nil
		}
		c := tx.Bucket([]byte(tierPrefix + t.Name)).Cursor()
		end := ownerKey(ownerID, hi)
		for k, v := c.Seek(ownerKey(ownerID, lo)); k != nil && string(k) < string(end); k, v = c.Next() {
			if len(k) != 12 {
				continue
			}
			if err := decodeRow(v, want, fold(int64(binary.BigEndian.Uint64(k[4:])))); err != nil {
				return err
			}
		}
		return nil
	}
	fromUnix := floorUnix(from.Unix(), db.tiers[ti].Res)
	toUnix := to.Unix()
	err := db.bolt.View(func(tx *bolt.Tx) error {
		if ti == 0 {
			return scan(tx, db.tiers[0], fromUnix, toUnix)
		}
		// The rolled part from the chosen tier, the rest from the finest.
		split := toUnix
		if rolledEnd < split {
			split = max(rolledEnd, fromUnix)
		}
		if err := scan(tx, db.tiers[ti], fromUnix, split); err != nil {
			return err
		}
		return scan(tx, db.tiers[0], max(split, floorUnix(from.Unix(), db.tiers[0].Res)), toUnix)
	})
	return acc, err
}
