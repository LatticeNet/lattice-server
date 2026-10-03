package store

import (
	"bytes"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The bolt half of monitor_rollups.go. A bucket record is keyed like a row,
// "<monitor_id>/<node_id>/<bucket start>", in monitor_rollup_fine (five-minute
// buckets) or monitor_rollup_coarse (one-hour buckets), so one pair's buckets
// sort by time and a seek reaches a window without touching other pairs.

var monitorRollupTiers = []struct {
	bucket []byte
	res    time.Duration
}{
	{boltBucketMonRollupFine, MonitorRollupFine},
	{boltBucketMonRollupCoarse, MonitorRollupCoarse},
}

func monitorRollupBucket(res time.Duration) ([]byte, error) {
	for _, tier := range monitorRollupTiers {
		if tier.res == res {
			return tier.bucket, nil
		}
	}
	return nil, fmt.Errorf("no monitor rollup at %s", res)
}

// addMonitorRollupsTx counts one stored result in both tiers. The caller has
// just written the result's row, so a duplicate never reaches here. A result
// whose bucket starts before a tier's retention line is not counted there:
// the trim below would delete that bucket the moment it was written.
func addMonitorRollupsTx(tx *bolt.Tx, rec MonitorResultRecord) error {
	newest := rec.At
	if rec.ReceivedAt.After(newest) {
		newest = rec.ReceivedAt
	}
	for _, tier := range monitorRollupTiers {
		start := rec.At.UTC().Truncate(tier.res)
		cutoff := newest.Add(-monitorRollupKeep(tier.res))
		if start.Before(cutoff) {
			continue
		}
		key := monitorResultKey(rec.MonitorID, rec.NodeID, start)
		var bucket MonitorRollup
		existed, err := getRecord(tx, tier.bucket, key, &bucket)
		if err != nil {
			return err
		}
		bucket.add(rec.Success, rec.LatencyMs)
		if err := putRecord(tx, tier.bucket, key, bucket); err != nil {
			return err
		}
		if existed {
			continue
		}
		// A new bucket is the only moment an old one can have aged out, so
		// the trim runs here and touches at most the few buckets that just
		// crossed the line.
		if err := trimMonitorRollupsTx(tx.Bucket(tier.bucket), rec.MonitorID, rec.NodeID, cutoff); err != nil {
			return err
		}
	}
	return nil
}

// trimMonitorRollupsTx deletes the pair's buckets that start before cutoff.
func trimMonitorRollupsTx(b *bolt.Bucket, monitorID, nodeID string, cutoff time.Time) error {
	prefix, err := monitorPairPrefix(monitorID, nodeID)
	if err != nil {
		return err
	}
	bound, err := boltStringKey(monitorResultKey(monitorID, nodeID, cutoff))
	if err != nil {
		return err
	}
	var stale [][]byte
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix) && bytes.Compare(k, bound) < 0; k, _ = c.Next() {
		stale = append(stale, append([]byte(nil), k...))
	}
	for _, k := range stale {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// deleteMonitorRollupsTx removes every bucket under prefix in both tiers.
func deleteMonitorRollupsTx(tx *bolt.Tx, prefix []byte) error {
	for _, tier := range monitorRollupTiers {
		if _, err := deleteKeysWithPrefixTx(tx.Bucket(tier.bucket), prefix); err != nil {
			return err
		}
	}
	return nil
}

// MonitorRollups reads each pair's buckets at res whose start lies in
// [from, to), oldest first.
func (bs *BoltStateStore) MonitorRollups(pairs []MonitorPair, res time.Duration, from, to time.Time) (map[MonitorPair][]MonitorRollup, error) {
	bucketName, err := monitorRollupBucket(res)
	if err != nil {
		return nil, err
	}
	out := map[MonitorPair][]MonitorRollup{}
	err = bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		for _, pair := range pairs {
			if validMonitorPair(pair.MonitorID, pair.NodeID) != nil {
				continue
			}
			prefix, err := monitorPairPrefix(pair.MonitorID, pair.NodeID)
			if err != nil {
				return err
			}
			first, err := boltStringKey(monitorResultKey(pair.MonitorID, pair.NodeID, from))
			if err != nil {
				return err
			}
			c := b.Cursor()
			for k, v := c.Seek(first); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				key, err := stringFromBoltKey(k)
				if err != nil {
					return err
				}
				_, _, at, ok := splitMonitorResultKey(key)
				if !ok {
					return fmt.Errorf("decode %s key %q", bucketName, key)
				}
				if !at.Before(to) {
					break
				}
				var bucket MonitorRollup
				if err := decodeRecordValue(bucketName, key, v, &bucket); err != nil {
					return err
				}
				bucket.At = at
				out[pair] = append(out[pair], bucket)
			}
		}
		return nil
	})
	return out, err
}
