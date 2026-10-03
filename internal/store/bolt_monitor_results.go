package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The bolt half of monitor_results.go. Rows go in monitor_result_rows keyed
// "<monitor_id>/<node_id>/<instant>"; each pair's latest record goes in
// monitor_result_latest keyed "<monitor_id>/<node_id>". Keys are JSON strings
// like every other bucket, and the instant is fixed width, so one pair's rows
// sort by time and a prefix seek reaches them without touching other pairs.
//
// The legacy monitor_results bucket held one series per monitor. The runtime
// never wrote it in the hot store; the full-state import and export used it,
// and the export still reads it so an older state.db exported to JSON keeps
// its history.

// boltKeyMonitorResultsMigrated records that State.MonResults was copied into
// the hot store. Like the KV and Static move it is a flag, not "is the bucket
// empty": the JSON file keeps its stale copy until the next write, and a
// second import would resurrect rows deleted since.
var boltKeyMonitorResultsMigrated = []byte("monitor_results_migrated")

// monitorResultRow is a row's value. The monitor, node and instant are in the
// key, so the value carries only the outcome.
type monitorResultRow struct {
	Success      bool      `json:"success"`
	LatencyMs    float64   `json:"latency_ms,omitzero"`
	Error        string    `json:"error,omitempty"`
	CertNotAfter time.Time `json:"cert_not_after,omitzero"`
	ReceivedAt   time.Time `json:"received_at,omitzero"`
}

func monitorRowFromRecord(rec MonitorResultRecord) monitorResultRow {
	return monitorResultRow{
		Success:      rec.Success,
		LatencyMs:    rec.LatencyMs,
		Error:        rec.Error,
		CertNotAfter: rec.CertNotAfter,
		ReceivedAt:   rec.ReceivedAt,
	}
}

func decodeMonitorResultRow(k, v []byte) (MonitorResultRecord, error) {
	key, err := stringFromBoltKey(k)
	if err != nil {
		return MonitorResultRecord{}, fmt.Errorf("decode %s key: %w", boltBucketMonResultRows, err)
	}
	monitorID, nodeID, at, ok := splitMonitorResultKey(key)
	if !ok {
		return MonitorResultRecord{}, fmt.Errorf("decode %s key %q: not <monitor>/<node>/<instant>", boltBucketMonResultRows, key)
	}
	var row monitorResultRow
	if err := decodeRecordValue(boltBucketMonResultRows, key, v, &row); err != nil {
		return MonitorResultRecord{}, err
	}
	rec := MonitorResultRecord{ReceivedAt: row.ReceivedAt}
	rec.MonitorID, rec.NodeID, rec.At = monitorID, nodeID, at
	rec.Success, rec.LatencyMs, rec.Error, rec.CertNotAfter = row.Success, row.LatencyMs, row.Error, row.CertNotAfter
	return rec, nil
}

// boltKeyPrefix is the encoded form of a key prefix: the JSON string with
// its closing quote removed, as usageDayPrefix builds it.
func boltKeyPrefix(prefix string) ([]byte, error) {
	enc, err := boltStringKey(prefix)
	if err != nil {
		return nil, err
	}
	return enc[:len(enc)-1], nil
}

// prefixUpperBound is the smallest key past every key with prefix. Every
// prefix here ends in '/', so incrementing that byte cannot overflow.
func prefixUpperBound(prefix []byte) []byte {
	bound := append([]byte(nil), prefix...)
	bound[len(bound)-1]++
	return bound
}

// lastWithPrefix positions c on the newest key with prefix.
func lastWithPrefix(c *bolt.Cursor, prefix []byte) ([]byte, []byte) {
	k, v := c.Seek(prefixUpperBound(prefix))
	if k == nil {
		k, v = c.Last()
	} else {
		k, v = c.Prev()
	}
	if k == nil || !bytes.HasPrefix(k, prefix) {
		return nil, nil
	}
	return k, v
}

func monitorPairPrefix(monitorID, nodeID string) ([]byte, error) {
	return boltKeyPrefix(monitorPairKey(monitorID, nodeID) + "/")
}

// recordMonitorResultTx writes one result for its pair: the row, its count
// in the rollups, the advanced latest record, and the trim to perPair. A row
// already held at the same instant is a duplicate and changes nothing.
func recordMonitorResultTx(tx *bolt.Tx, rec MonitorResultRecord, perPair int) (MonitorResultOutcome, error) {
	out := MonitorResultOutcome{Result: rec}
	rows := tx.Bucket(boltBucketMonResultRows)
	if rows == nil {
		return out, fmt.Errorf("missing bucket %q", string(boltBucketMonResultRows))
	}
	pairKey := monitorPairKey(rec.MonitorID, rec.NodeID)
	var prior MonitorLatest
	hadPrior, err := getRecord(tx, boltBucketMonResultLatest, pairKey, &prior)
	if err != nil {
		return out, err
	}
	out.PriorFailStreak = prior.FailStreak
	rowKey, err := boltStringKey(monitorResultKey(rec.MonitorID, rec.NodeID, rec.At))
	if err != nil {
		return out, err
	}
	if rows.Get(rowKey) != nil {
		out.Duplicate = true
		return out, nil
	}
	data, err := json.Marshal(monitorRowFromRecord(rec))
	if err != nil {
		return out, err
	}
	if err := rows.Put(rowKey, data); err != nil {
		return out, err
	}
	if err := addMonitorRollupsTx(tx, rec); err != nil {
		return out, err
	}
	next := advanceMonitorLatest(prior, hadPrior, rec)
	prefix, err := monitorPairPrefix(rec.MonitorID, rec.NodeID)
	if err != nil {
		return out, err
	}
	if err := trimMonitorPairTx(rows, prefix, &next, perPair); err != nil {
		return out, err
	}
	return out, putRecord(tx, boltBucketMonResultLatest, pairKey, next)
}

// trimMonitorPairTx deletes the pair's oldest rows beyond perPair. Held is
// trusted to say how many rows there are; if the walk runs out of rows first,
// Held had drifted, and the rows actually present decide instead, so a wrong
// count can never delete the row just written.
func trimMonitorPairTx(rows *bolt.Bucket, prefix []byte, latest *MonitorLatest, perPair int) error {
	excess := latest.Held - perPair
	if excess <= 0 {
		return nil
	}
	var stale [][]byte
	exhausted := true
	c := rows.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		if len(stale) == excess {
			exhausted = false
			break
		}
		stale = append(stale, append([]byte(nil), k...))
	}
	if exhausted {
		present := len(stale)
		latest.Held = present
		if present <= perPair {
			return nil
		}
		stale = stale[:present-perPair]
	}
	for _, k := range stale {
		if err := rows.Delete(k); err != nil {
			return err
		}
	}
	latest.Held -= len(stale)
	return nil
}

// RecordMonitorResults writes results in order, in one transaction.
func (bs *BoltStateStore) RecordMonitorResults(records []MonitorResultRecord, perPair int) ([]MonitorResultOutcome, error) {
	outcomes := make([]MonitorResultOutcome, len(records))
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for i, rec := range records {
			out, err := recordMonitorResultTx(tx, rec, perPair)
			if err != nil {
				return err
			}
			outcomes[i] = out
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return outcomes, nil
}

// importMonitorResultSeriesTx records JSON-shaped series (arrival order per
// monitor) through the same path live results take, so the latest records,
// streaks and trims come out exactly as if the results had arrived here.
func importMonitorResultSeriesTx(tx *bolt.Tx, series map[string][]MonitorResultRecord, perPair int) error {
	monitorIDs := make([]string, 0, len(series))
	for monitorID := range series {
		monitorIDs = append(monitorIDs, monitorID)
	}
	sort.Strings(monitorIDs)
	for _, monitorID := range monitorIDs {
		for _, rec := range series[monitorID] {
			rec.MonitorID = monitorID
			if rec.At.IsZero() || validMonitorPair(rec.MonitorID, rec.NodeID) != nil {
				// Nothing could key it, and nothing ever read it.
				continue
			}
			rec.At = rec.At.UTC()
			if _, err := recordMonitorResultTx(tx, rec, perPair); err != nil {
				return err
			}
		}
	}
	return nil
}

// MigrateMonitorResults copies State.MonResults into the hot store, once.
func (bs *BoltStateStore) MigrateMonitorResults(series map[string][]MonitorResultRecord, perPair int) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		meta := tx.Bucket(boltBucketMeta)
		if meta == nil {
			return fmt.Errorf("missing bucket %q", string(boltBucketMeta))
		}
		if meta.Get(boltKeyMonitorResultsMigrated) != nil {
			return nil
		}
		if err := importMonitorResultSeriesTx(tx, series, perPair); err != nil {
			return err
		}
		return meta.Put(boltKeyMonitorResultsMigrated, []byte("1"))
	})
}

func (bs *BoltStateStore) MonitorLatest(monitorID, nodeID string) (MonitorLatest, bool, error) {
	var latest MonitorLatest
	var ok bool
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		var err error
		ok, err = getRecord(tx, boltBucketMonResultLatest, monitorPairKey(monitorID, nodeID), &latest)
		return err
	})
	return latest, ok, err
}

// LatestMonitorResults reads every pair's latest record: one record per
// pair, so the cost is the number of pairs, not of rows.
func (bs *BoltStateStore) LatestMonitorResults() (map[string][]MonitorLatest, error) {
	out := map[string][]MonitorLatest{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketMonResultLatest)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			key, err := stringFromBoltKey(k)
			if err != nil {
				return err
			}
			monitorID, _, ok := splitMonitorPairKey(key)
			if !ok {
				return fmt.Errorf("decode %s key %q", boltBucketMonResultLatest, key)
			}
			var latest MonitorLatest
			if err := decodeRecordValue(boltBucketMonResultLatest, key, v, &latest); err != nil {
				return err
			}
			out[monitorID] = append(out[monitorID], latest)
			return nil
		})
	})
	for _, pairs := range out {
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].NodeID < pairs[j].NodeID })
	}
	return out, err
}

// MonitorPairResults is one pair's newest limit rows, oldest first, read
// backwards from the pair's end.
func (bs *BoltStateStore) MonitorPairResults(monitorID, nodeID string, limit int) ([]MonitorResultRecord, error) {
	out := []MonitorResultRecord{}
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
		c := rows.Cursor()
		for k, v := lastWithPrefix(c, prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Prev() {
			if limit > 0 && len(out) == limit {
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
	reverseMonitorRecords(out)
	return out, err
}

// RecentMonitorResults merges the pairs of one monitor from their newest
// rows backwards and stops at limit, so the cost is limit rows plus one seek
// per pair, however much history each pair holds.
func (bs *BoltStateStore) RecentMonitorResults(monitorID string, limit int, allow func(nodeID string) bool) ([]MonitorResultRecord, error) {
	out := []MonitorResultRecord{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		rows := tx.Bucket(boltBucketMonResultRows)
		latest := tx.Bucket(boltBucketMonResultLatest)
		if rows == nil || latest == nil {
			return nil
		}
		monitorPrefix, err := boltKeyPrefix(monitorID + "/")
		if err != nil {
			return err
		}
		type head struct {
			c      *bolt.Cursor
			prefix []byte
			k, v   []byte
		}
		var heads []*head
		lc := latest.Cursor()
		for k, _ := lc.Seek(monitorPrefix); k != nil && bytes.HasPrefix(k, monitorPrefix); k, _ = lc.Next() {
			key, err := stringFromBoltKey(k)
			if err != nil {
				return err
			}
			_, nodeID, ok := splitMonitorPairKey(key)
			if !ok || (allow != nil && !allow(nodeID)) {
				continue
			}
			prefix, err := monitorPairPrefix(monitorID, nodeID)
			if err != nil {
				return err
			}
			h := &head{c: rows.Cursor(), prefix: prefix}
			h.k, h.v = lastWithPrefix(h.c, prefix)
			if h.k != nil {
				heads = append(heads, h)
			}
		}
		for limit <= 0 || len(out) < limit {
			var best *head
			for _, h := range heads {
				if h.k == nil {
					continue
				}
				// Keys end in the fixed-width instant and a closing quote,
				// so the instant compares as bytes across pairs.
				if best == nil || bytes.Compare(instantOfRowKey(h.k), instantOfRowKey(best.k)) > 0 {
					best = h
				}
			}
			if best == nil {
				break
			}
			rec, err := decodeMonitorResultRow(best.k, best.v)
			if err != nil {
				return err
			}
			out = append(out, rec)
			best.k, best.v = best.c.Prev()
			if best.k != nil && !bytes.HasPrefix(best.k, best.prefix) {
				best.k, best.v = nil, nil
			}
		}
		return nil
	})
	reverseMonitorRecords(out)
	return out, err
}

// instantOfRowKey is the instant segment of an encoded row key.
func instantOfRowKey(k []byte) []byte {
	n := len(monitorResultLayout) + 1
	if len(k) < n {
		return k
	}
	return k[len(k)-n : len(k)-1]
}

func reverseMonitorRecords(rows []MonitorResultRecord) {
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
}

func (bs *BoltStateStore) NewestMonitorResult(monitorID, nodeID string, match func(MonitorResultRecord) bool) (MonitorResultRecord, bool, error) {
	var found MonitorResultRecord
	var ok bool
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
		c := rows.Cursor()
		for k, v := lastWithPrefix(c, prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Prev() {
			rec, err := decodeMonitorResultRow(k, v)
			if err != nil {
				return err
			}
			if match(rec) {
				found, ok = rec, true
				return nil
			}
		}
		return nil
	})
	return found, ok, err
}

// deleteKeysWithPrefixTx deletes every key with prefix. Keys are collected
// first: deleting under a cursor that is still walking can skip keys.
func deleteKeysWithPrefixTx(b *bolt.Bucket, prefix []byte) (int, error) {
	if b == nil {
		return 0, nil
	}
	var keys [][]byte
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		keys = append(keys, append([]byte(nil), k...))
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
}

// deleteMonitorResultsTx removes a monitor's rows, rollups and latest
// records.
func deleteMonitorResultsTx(tx *bolt.Tx, monitorID string) error {
	prefix, err := boltKeyPrefix(monitorID + "/")
	if err != nil {
		return err
	}
	if _, err := deleteKeysWithPrefixTx(tx.Bucket(boltBucketMonResultRows), prefix); err != nil {
		return err
	}
	if err := deleteMonitorRollupsTx(tx, prefix); err != nil {
		return err
	}
	_, err = deleteKeysWithPrefixTx(tx.Bucket(boltBucketMonResultLatest), prefix)
	return err
}

// DeleteMonitorResults removes a monitor's history; the monitor record itself
// lives in the JSON state when this is the hot store.
func (bs *BoltStateStore) DeleteMonitorResults(monitorID string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteMonitorResultsTx(tx, monitorID)
	})
}

// monitorPairsForNodeTx lists the pair keys whose node is nodeID, read off
// the latest bucket: a pair with rows always has a latest record.
func monitorPairsForNodeTx(tx *bolt.Tx, nodeID string, visit func(key string, latest MonitorLatest) error) error {
	b := tx.Bucket(boltBucketMonResultLatest)
	if b == nil {
		return nil
	}
	type pair struct {
		key    string
		latest MonitorLatest
	}
	var pairs []pair
	if err := b.ForEach(func(k, v []byte) error {
		key, err := stringFromBoltKey(k)
		if err != nil {
			return err
		}
		_, owner, ok := splitMonitorPairKey(key)
		if !ok || owner != nodeID {
			return nil
		}
		var latest MonitorLatest
		if err := decodeRecordValue(boltBucketMonResultLatest, key, v, &latest); err != nil {
			return err
		}
		pairs = append(pairs, pair{key: key, latest: latest})
		return nil
	}); err != nil {
		return err
	}
	for _, p := range pairs {
		if err := visit(p.key, p.latest); err != nil {
			return err
		}
	}
	return nil
}

// MonitorResultsHeldForNode sums the rows a node's pairs hold.
func (bs *BoltStateStore) MonitorResultsHeldForNode(nodeID string) (int, error) {
	held := 0
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return monitorPairsForNodeTx(tx, nodeID, func(_ string, latest MonitorLatest) error {
			held += latest.Held
			return nil
		})
	})
	return held, err
}

// DeleteMonitorResultsForNode removes every pair of a deleted node. Left
// behind, a node enrolled again under the same id would inherit the streak,
// and its first result could page on one failure or announce a recovery from
// a page it never had.
func (bs *BoltStateStore) DeleteMonitorResultsForNode(nodeID string) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return monitorPairsForNodeTx(tx, nodeID, func(key string, _ MonitorLatest) error {
			prefix, err := boltKeyPrefix(key + "/")
			if err != nil {
				return err
			}
			if _, err := deleteKeysWithPrefixTx(tx.Bucket(boltBucketMonResultRows), prefix); err != nil {
				return err
			}
			if err := deleteMonitorRollupsTx(tx, prefix); err != nil {
				return err
			}
			return deleteRecord(tx, boltBucketMonResultLatest, key)
		})
	})
}

// readMonitorResultRowsTx rebuilds JSON-shaped series from the rows, each
// monitor's series ordered by instant, for the full export.
func readMonitorResultRowsTx(tx *bolt.Tx, out map[string][]MonitorResultRecord) error {
	rows := tx.Bucket(boltBucketMonResultRows)
	if rows == nil {
		return nil
	}
	if err := rows.ForEach(func(k, v []byte) error {
		rec, err := decodeMonitorResultRow(k, v)
		if err != nil {
			return err
		}
		out[rec.MonitorID] = append(out[rec.MonitorID], rec)
		return nil
	}); err != nil {
		return err
	}
	for _, series := range out {
		sort.SliceStable(series, func(i, j int) bool { return series[i].At.Before(series[j].At) })
	}
	return nil
}
