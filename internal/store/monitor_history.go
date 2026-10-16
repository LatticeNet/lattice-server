package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Monitor history reads for the paths matrix, the hourly pruning sweep and
// the size the history occupies. Every read here runs in one bolt read
// transaction outside the store lock (hotForMonitorRead), so a week of
// rollups for every path never holds up ingest.

// MonitorWindowSummary is one pair's results over a window (Cur) and over the
// window of the same length just before it (Prev), each merged into one
// bucket.
type MonitorWindowSummary struct {
	Cur  MonitorRollup
	Prev MonitorRollup
}

// MonitorRollupSummaries merges each pair's buckets at res into the window
// [from, to) and the window before it, [prevFrom, from), in one read. A pair
// with no bucket in either has no entry. Bucket starts are compared, as
// MonitorRollups does, so from and prevFrom are aligned to res first.
func (s *Store) MonitorRollupSummaries(pairs []MonitorPair, res time.Duration, prevFrom, from, to time.Time) (map[MonitorPair]MonitorWindowSummary, error) {
	prevFrom, from, to = prevFrom.UTC().Truncate(res), from.UTC().Truncate(res), to.UTC()
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.MonitorRollupSummaries(pairs, res, prevFrom, from, to)
	}
	defer s.mu.Unlock()
	out := map[MonitorPair]MonitorWindowSummary{}
	for _, pair := range pairs {
		var sum MonitorWindowSummary
		for _, b := range RollupMonitorResults(s.jsonPairRowsLocked(pair), res, prevFrom, to) {
			if b.At.Before(from) {
				sum.Prev.Merge(b)
			} else {
				sum.Cur.Merge(b)
			}
		}
		if sum.Cur.N+sum.Prev.N > 0 {
			out[pair] = sum
		}
	}
	return out, nil
}

// MonitorRowSummaries summarizes each pair's raw rows stamped in [from, to)
// and in [prevFrom, from), jitter included, in one read. The raw tier
// answers the shortest window exactly, without bucket edges.
func (s *Store) MonitorRowSummaries(pairs []MonitorPair, prevFrom, from, to time.Time) (map[MonitorPair]MonitorWindowSummary, error) {
	prevFrom, from, to = prevFrom.UTC(), from.UTC(), to.UTC()
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.MonitorRowSummaries(pairs, prevFrom, from, to)
	}
	defer s.mu.Unlock()
	out := map[MonitorPair]MonitorWindowSummary{}
	for _, pair := range pairs {
		if sum, ok := summarizeMonitorRows(s.jsonPairRowsLocked(pair), prevFrom, from, to); ok {
			out[pair] = sum
		}
	}
	return out, nil
}

// summarizeMonitorRows splits one pair's rows (oldest first) at from. A
// success in the earlier window is the predecessor of the first one in the
// later window, as it would be in the hot store's buckets.
func summarizeMonitorRows(rows []MonitorResultRecord, prevFrom, from, to time.Time) (MonitorWindowSummary, bool) {
	var sum MonitorWindowSummary
	var lastAt time.Time
	var lastMs float64
	for _, rec := range rows {
		if rec.At.Before(prevFrom) || !rec.At.Before(to) {
			continue
		}
		into := &sum.Cur
		if rec.At.Before(from) {
			into = &sum.Prev
		}
		into.add(rec.Success, rec.LatencyMs)
		if !rec.Success {
			continue
		}
		if delta, ok := monitorJitterDelta(lastAt, lastMs, rec.At, rec.LatencyMs); ok {
			into.addJitter(delta)
		}
		lastAt, lastMs = rec.At, rec.LatencyMs
	}
	return sum, sum.Cur.N+sum.Prev.N > 0
}

// jsonPairRowsLocked is one pair's rows in the JSON state, oldest first.
func (s *Store) jsonPairRowsLocked(pair MonitorPair) []MonitorResultRecord {
	var rows []MonitorResultRecord
	for _, r := range s.state.MonResults[pair.MonitorID] {
		if r.NodeID == pair.NodeID {
			rows = append(rows, r)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.Before(rows[j].At) })
	return rows
}

// MonitorRollupSummaries is the bolt half: one seek per pair, and each bucket
// decoded into a scratch record whose histogram map is reused.
func (bs *BoltStateStore) MonitorRollupSummaries(pairs []MonitorPair, res time.Duration, prevFrom, from, to time.Time) (map[MonitorPair]MonitorWindowSummary, error) {
	bucketName, err := monitorRollupBucket(res)
	if err != nil {
		return nil, err
	}
	out := make(map[MonitorPair]MonitorWindowSummary, len(pairs))
	err = bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		fromInstant := []byte(from.Format(monitorResultLayout))
		toInstant := []byte(to.Format(monitorResultLayout))
		var scratch MonitorRollup
		c := b.Cursor()
		for _, pair := range pairs {
			if validMonitorPair(pair.MonitorID, pair.NodeID) != nil {
				continue
			}
			prefix, err := monitorPairPrefix(pair.MonitorID, pair.NodeID)
			if err != nil {
				return err
			}
			first, err := boltStringKey(monitorResultKey(pair.MonitorID, pair.NodeID, prevFrom))
			if err != nil {
				return err
			}
			var sum MonitorWindowSummary
			for k, v := c.Seek(first); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				instant := instantOfRowKey(k)
				if bytes.Compare(instant, toInstant) >= 0 {
					break
				}
				clear(scratch.H)
				h := scratch.H
				scratch = MonitorRollup{H: h}
				if err := json.Unmarshal(v, &scratch); err != nil {
					return fmt.Errorf("decode %s value: %w", bucketName, err)
				}
				if bytes.Compare(instant, fromInstant) < 0 {
					sum.Prev.Merge(scratch)
				} else {
					sum.Cur.Merge(scratch)
				}
			}
			if sum.Cur.N+sum.Prev.N > 0 {
				out[pair] = sum
			}
		}
		return nil
	})
	return out, err
}

// MonitorRowSummaries is the bolt half: rows are read forward from prevFrom,
// so they arrive oldest first, as the jitter count needs.
func (bs *BoltStateStore) MonitorRowSummaries(pairs []MonitorPair, prevFrom, from, to time.Time) (map[MonitorPair]MonitorWindowSummary, error) {
	out := make(map[MonitorPair]MonitorWindowSummary, len(pairs))
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		rows := tx.Bucket(boltBucketMonResultRows)
		if rows == nil {
			return nil
		}
		toInstant := []byte(to.Format(monitorResultLayout))
		c := rows.Cursor()
		var recs []MonitorResultRecord
		for _, pair := range pairs {
			if validMonitorPair(pair.MonitorID, pair.NodeID) != nil {
				continue
			}
			prefix, err := monitorPairPrefix(pair.MonitorID, pair.NodeID)
			if err != nil {
				return err
			}
			first, err := boltStringKey(monitorResultKey(pair.MonitorID, pair.NodeID, prevFrom))
			if err != nil {
				return err
			}
			recs = recs[:0]
			for k, v := c.Seek(first); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				instant := instantOfRowKey(k)
				if bytes.Compare(instant, toInstant) >= 0 {
					break
				}
				// The pair is known, so only the instant is read off the
				// key; a summary needs the outcome and the latency.
				at, err := time.Parse(monitorResultLayout, string(instant))
				if err != nil {
					return fmt.Errorf("decode %s key instant %q: %w", boltBucketMonResultRows, instant, err)
				}
				var row monitorResultRow
				if err := json.Unmarshal(v, &row); err != nil {
					return fmt.Errorf("decode %s value: %w", boltBucketMonResultRows, err)
				}
				rec := MonitorResultRecord{}
				rec.At, rec.Success, rec.LatencyMs = at, row.Success, row.LatencyMs
				recs = append(recs, rec)
			}
			if sum, ok := summarizeMonitorRows(recs, prevFrom, from, to); ok {
				out[pair] = sum
			}
		}
		return nil
	})
	return out, err
}

// MonitorPruneReport counts what one pruning sweep deleted.
type MonitorPruneReport struct {
	Rows         int
	Fine         int
	Coarse       int
	Transactions int
}

// monitorPruneBatch bounds the deletes in one write transaction. Ingest
// waits for the bolt writer while it holds the store lock, so the sweep must
// never hold the writer for long: a couple of thousand deletes is a few
// milliseconds.
const monitorPruneBatch = 2000

// PruneMonitorHistory deletes, for every pair, the rollup buckets and raw
// rows behind each tier's retention line as of now: fine buckets older than
// the fine retention, coarse buckets older than the coarse one, and raw rows
// older than the coarse one. Active pairs already trim as their results
// arrive; this reaches the pairs that stopped (a paused source, a source
// taken off a check, a paused generated check, a disabled check) and a
// retention the operator lowered. It runs without the store lock, in write
// transactions of at most monitorPruneBatch deletes, and stops between
// them once ctx is done.
func (s *Store) PruneMonitorHistory(ctx context.Context, now time.Time) (MonitorPruneReport, error) {
	s.mu.Lock()
	limits := monitorHistoryLimitsOf(s.state.MonitorSettings)
	hot := s.runtimeBoltHot
	if hot == nil {
		defer s.mu.Unlock()
		return s.pruneJSONMonitorRowsLocked(now.Add(-limits.rawKeep()))
	}
	s.mu.Unlock()
	return hot.PruneMonitorHistory(ctx, now, limits, monitorPruneBatch)
}

// pruneJSONMonitorRowsLocked is the sweep without the hot store, which keeps
// no rollups: rows older than cutoff go, and the file is written only when
// one did.
func (s *Store) pruneJSONMonitorRowsLocked(cutoff time.Time) (MonitorPruneReport, error) {
	var report MonitorPruneReport
	prior := map[string][]MonitorResultRecord{}
	for monitorID, series := range s.state.MonResults {
		kept := make([]MonitorResultRecord, 0, len(series))
		for _, r := range series {
			if r.At.Before(cutoff) {
				report.Rows++
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) != len(series) {
			prior[monitorID] = series
			s.state.MonResults[monitorID] = kept
		}
	}
	if report.Rows == 0 {
		return report, nil
	}
	if err := s.Save(); err != nil {
		for monitorID, series := range prior {
			s.state.MonResults[monitorID] = series
		}
		return MonitorPruneReport{}, err
	}
	report.Transactions = 1
	return report, nil
}

// PruneMonitorHistory is the bolt half. Each tier is scanned in a read
// transaction for the pairs whose oldest key is behind the line, so a sweep
// that finds nothing writes nothing; those pairs are then trimmed in bounded
// write transactions that check every key again.
func (bs *BoltStateStore) PruneMonitorHistory(ctx context.Context, now time.Time, limits MonitorHistoryLimits, batch int) (MonitorPruneReport, error) {
	if batch <= 0 {
		batch = monitorPruneBatch
	}
	var report MonitorPruneReport
	tiers := []struct {
		bucket []byte
		cutoff time.Time
		count  *int
		rows   bool
	}{
		{boltBucketMonRollupFine, now.Add(-limits.keep(MonitorRollupFine)), &report.Fine, false},
		{boltBucketMonRollupCoarse, now.Add(-limits.keep(MonitorRollupCoarse)), &report.Coarse, false},
		{boltBucketMonResultRows, now.Add(-limits.rawKeep()), &report.Rows, true},
	}
	for _, tier := range tiers {
		instant := []byte(tier.cutoff.UTC().Format(monitorResultLayout))
		stale, err := bs.staleMonitorPairs(tier.bucket, instant)
		if err != nil {
			return report, err
		}
		for len(stale) > 0 {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			var deleted int
			err := bs.db.Update(func(tx *bolt.Tx) error {
				if err := checkBoltVersion(tx); err != nil {
					return err
				}
				b := tx.Bucket(tier.bucket)
				if b == nil {
					stale = nil
					return nil
				}
				deleted = 0
				for len(stale) > 0 && deleted < batch {
					n, done, err := pruneMonitorPairTx(tx, b, stale[0], instant, batch-deleted, tier.rows)
					if err != nil {
						return err
					}
					deleted += n
					if !done {
						break
					}
					stale = stale[1:]
				}
				return nil
			})
			if err != nil {
				return report, err
			}
			*tier.count += deleted
			report.Transactions++
		}
	}
	return report, nil
}

// staleMonitorPairs lists the encoded pair prefixes ("<monitor>/<node>/ with
// its opening quote) in bucket whose oldest key is behind instant. It visits
// each pair once: a seek past the pair's prefix lands on the next pair.
func (bs *BoltStateStore) staleMonitorPairs(bucket, instant []byte) ([][]byte, error) {
	var stale [][]byte
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(bucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; {
			prefix := monitorKeyPairPrefix(k)
			if prefix == nil {
				// Not a pair key; nothing written here makes one, so skip
				// it rather than fail the sweep.
				k, _ = c.Next()
				continue
			}
			if bytes.Compare(instantOfRowKey(k), instant) < 0 {
				stale = append(stale, append([]byte(nil), prefix...))
			}
			k, _ = c.Seek(prefixUpperBound(prefix))
		}
		return nil
	})
	return stale, err
}

// monitorKeyPairPrefix is the encoded pair prefix of an encoded row or
// bucket key: everything up to and including the slash before the instant.
// Ids never hold a slash and the encoder never escapes one.
func monitorKeyPairPrefix(k []byte) []byte {
	i := bytes.LastIndexByte(k, '/')
	if i <= 0 || len(k)-i-2 != len(monitorResultLayout) {
		return nil
	}
	return k[:i+1]
}

// pruneMonitorPairTx deletes up to budget of the pair's keys behind instant.
// done is false when the budget ran out first. For raw rows it lowers the
// pair's Held by what it deleted, in the same transaction.
func pruneMonitorPairTx(tx *bolt.Tx, b *bolt.Bucket, prefix, instant []byte, budget int, rows bool) (int, bool, error) {
	var keys [][]byte
	done := true
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		if bytes.Compare(instantOfRowKey(k), instant) >= 0 {
			break
		}
		if len(keys) == budget {
			done = false
			break
		}
		keys = append(keys, append([]byte(nil), k...))
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return 0, false, err
		}
	}
	if !rows || len(keys) == 0 {
		return len(keys), done, nil
	}
	latestBucket := tx.Bucket(boltBucketMonResultLatest)
	if latestBucket == nil {
		return len(keys), done, nil
	}
	// The pair's latest key is its prefix without the trailing slash, closed.
	latestKey := append(append([]byte(nil), prefix[:len(prefix)-1]...), '"')
	raw := latestBucket.Get(latestKey)
	if raw == nil {
		return len(keys), done, nil
	}
	var latest MonitorLatest
	if err := json.Unmarshal(raw, &latest); err != nil {
		return 0, false, fmt.Errorf("decode %s value: %w", boltBucketMonResultLatest, err)
	}
	latest.Held = max(latest.Held-len(keys), 0)
	data, err := json.Marshal(latest)
	if err != nil {
		return 0, false, err
	}
	return len(keys), done, latestBucket.Put(latestKey, data)
}

// MonitorStorageUsage is the size of the monitor history in the hot store,
// from bbolt's page statistics: bytes allocated to each bucket's pages and
// the keys each holds. Measured is false without the hot store.
type MonitorStorageUsage struct {
	Measured    bool
	RowBytes    int64
	LatestBytes int64
	FineBytes   int64
	CoarseBytes int64
	RowKeys     int
	LatestKeys  int
	FineKeys    int
	CoarseKeys  int
}

// Total is every monitor history bucket's bytes.
func (u MonitorStorageUsage) Total() int64 {
	return u.RowBytes + u.LatestBytes + u.FineBytes + u.CoarseBytes
}

// MonitorStorageUsage reads the bucket statistics outside the store lock.
func (s *Store) MonitorStorageUsage() (MonitorStorageUsage, error) {
	hot := s.hotForMonitorRead()
	if hot == nil {
		s.mu.Unlock()
		return MonitorStorageUsage{}, nil
	}
	return hot.MonitorStorageUsage()
}

func (bs *BoltStateStore) MonitorStorageUsage() (MonitorStorageUsage, error) {
	out := MonitorStorageUsage{Measured: true}
	err := bs.db.View(func(tx *bolt.Tx) error {
		for _, part := range []struct {
			bucket []byte
			bytes  *int64
			keys   *int
		}{
			{boltBucketMonResultRows, &out.RowBytes, &out.RowKeys},
			{boltBucketMonResultLatest, &out.LatestBytes, &out.LatestKeys},
			{boltBucketMonRollupFine, &out.FineBytes, &out.FineKeys},
			{boltBucketMonRollupCoarse, &out.CoarseBytes, &out.CoarseKeys},
		} {
			b := tx.Bucket(part.bucket)
			if b == nil {
				continue
			}
			st := b.Stats()
			// A small bucket lives inline in its parent's page and owns
			// no pages of its own; what it uses there is its size.
			*part.bytes = int64(st.BranchAlloc + st.LeafAlloc + st.InlineBucketInuse)
			*part.keys = st.KeyN
		}
		return nil
	})
	return out, err
}

// MonitorOldestBuckets is each pair's oldest bucket start at res, which says
// how far back that tier actually reaches for the pair: a tier whose
// retention was raised, or that was shorter before an upgrade, holds less
// than its retention until it fills. A pair with no bucket has no entry.
func (s *Store) MonitorOldestBuckets(pairs []MonitorPair, res time.Duration) (map[MonitorPair]time.Time, error) {
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.MonitorOldestBuckets(pairs, res)
	}
	defer s.mu.Unlock()
	out := map[MonitorPair]time.Time{}
	for _, pair := range pairs {
		if rows := s.jsonPairRowsLocked(pair); len(rows) > 0 {
			out[pair] = rows[0].At.UTC().Truncate(res)
		}
	}
	return out, nil
}

func (bs *BoltStateStore) MonitorOldestBuckets(pairs []MonitorPair, res time.Duration) (map[MonitorPair]time.Time, error) {
	bucketName, err := monitorRollupBucket(res)
	if err != nil {
		return nil, err
	}
	out := make(map[MonitorPair]time.Time, len(pairs))
	err = bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for _, pair := range pairs {
			if validMonitorPair(pair.MonitorID, pair.NodeID) != nil {
				continue
			}
			prefix, err := monitorPairPrefix(pair.MonitorID, pair.NodeID)
			if err != nil {
				return err
			}
			k, _ := c.Seek(prefix)
			if k == nil || !bytes.HasPrefix(k, prefix) {
				continue
			}
			at, err := time.Parse(monitorResultLayout, string(instantOfRowKey(k)))
			if err != nil {
				return fmt.Errorf("decode %s key instant: %w", bucketName, err)
			}
			out[pair] = at
		}
		return nil
	})
	return out, err
}

// MonitorPairResultsBetween is one pair's rows stamped in [from, to), oldest
// first, read forward from from: a window, however many runs it holds.
func (s *Store) MonitorPairResultsBetween(monitorID, nodeID string, from, to time.Time) ([]MonitorResultRecord, error) {
	from, to = from.UTC(), to.UTC()
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.MonitorPairResultsBetween(monitorID, nodeID, from, to)
	}
	defer s.mu.Unlock()
	out := []MonitorResultRecord{}
	for _, r := range s.jsonPairRowsLocked(MonitorPair{MonitorID: monitorID, NodeID: nodeID}) {
		if !r.At.Before(from) && r.At.Before(to) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (bs *BoltStateStore) MonitorPairResultsBetween(monitorID, nodeID string, from, to time.Time) ([]MonitorResultRecord, error) {
	out := []MonitorResultRecord{}
	if validMonitorPair(monitorID, nodeID) != nil {
		return out, nil
	}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		rows := tx.Bucket(boltBucketMonResultRows)
		if rows == nil {
			return nil
		}
		prefix, err := monitorPairPrefix(monitorID, nodeID)
		if err != nil {
			return err
		}
		first, err := boltStringKey(monitorResultKey(monitorID, nodeID, from))
		if err != nil {
			return err
		}
		toInstant := []byte(to.Format(monitorResultLayout))
		c := rows.Cursor()
		for k, v := c.Seek(first); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if bytes.Compare(instantOfRowKey(k), toInstant) >= 0 {
				break
			}
			rec, err := decodeMonitorResultRow(k, v)
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, err
}
