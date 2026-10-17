package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	bolt "go.etcd.io/bbolt"
)

// Degraded paths (design 29 D13): the records the server's degraded
// evaluator keeps across a restart, and the baseline read it refreshes once
// an hour.
//
// A record is one pair that is degraded or clearing. It is written only when
// the pair enters, starts clearing, stops clearing or leaves, never once a
// minute, and never touches the state file. A pending pair (the condition
// found once) is not a record: a restart forgets it and the pair needs two
// fresh evaluations, as it would have.
//
// The bucket is record-level, like the incident buckets: not in
// boltStateBuckets, created on the first write, and deleted pair by pair
// with the rest of a pair's history (deleteMonitorResultsTx,
// DeleteMonitorResultsForNode). Without the hot store the records live in
// memory only, as incidents do there.

var boltBucketMonPathDegraded = []byte("monitor_path_degraded")

// PathDegradedRecord is one degraded or clearing pair. Since is the first of
// the evaluations that entered and EnteredAt the one that did; ClearSince is
// set while the condition is absent. Quiet marks a record that entered while
// the path read down or unknown, which never pages. Reason and the evidence
// are from the evaluation at EvaluatedAt: the entry when the record is read
// back after a restart, the latest one that found the condition while the
// server runs.
type PathDegradedRecord struct {
	Since       time.Time                  `json:"since"`
	EnteredAt   time.Time                  `json:"entered_at"`
	ClearSince  time.Time                  `json:"clear_since,omitzero"`
	Quiet       bool                       `json:"quiet,omitempty"`
	Reason      string                     `json:"reason"`
	EvaluatedAt time.Time                  `json:"evaluated_at"`
	Loss        *model.PathLossEvidence    `json:"loss,omitempty"`
	Latency     *model.PathLatencyEvidence `json:"latency,omitempty"`
}

// Clearing reports whether the condition is absent and the record is
// counting down to leaving.
func (r PathDegradedRecord) Clearing() bool { return !r.ClearSince.IsZero() }

// PathDegradedRecords reads every record. Pairs whose key does not parse are
// skipped; nothing writes such a key. With the hot store the bolt read runs
// outside the store lock (hotForMonitorRead), as M1's history reads do.
func (s *Store) PathDegradedRecords() (map[MonitorPair]PathDegradedRecord, error) {
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.PathDegradedRecords()
	}
	defer s.mu.Unlock()
	out := make(map[MonitorPair]PathDegradedRecord, len(s.pathDegraded))
	for pair, rec := range s.pathDegraded {
		out[pair] = rec
	}
	return out, nil
}

// monitorPairExistsLocked reports whether pair's monitor, and its node when
// it names one, still exist.
func (s *Store) monitorPairExistsLocked(pair MonitorPair) bool {
	if _, ok := s.state.Monitors[pair.MonitorID]; !ok {
		return false
	}
	if pair.NodeID != "" {
		if _, ok := s.state.Nodes[pair.NodeID]; !ok {
			return false
		}
	}
	return true
}

// PutPathDegradedRecord writes one pair's record. A pair whose monitor or
// node no longer exists is not written: a delete that ran while the
// evaluator was judging the pair must not leave a record behind it.
//
// With the hot store the bolt write (its fsync included) runs outside the
// store lock, so a slow disk holds up only other bolt writers, never every
// store caller. The existence check is therefore made again after the
// write: a delete that ran between the first check and the write removed
// the pair's records before this one landed, so the record is taken back.
// A delete after the second check removes it itself.
func (s *Store) PutPathDegradedRecord(pair MonitorPair, rec PathDegradedRecord) error {
	if err := validMonitorPair(pair.MonitorID, pair.NodeID); err != nil {
		return err
	}
	s.mu.Lock()
	hot, exists, beforeWrite := s.runtimeBoltHot, s.monitorPairExistsLocked(pair), s.testBeforePathDegradedWrite
	if hot == nil {
		defer s.mu.Unlock()
		if !exists {
			return nil
		}
		if s.pathDegraded == nil {
			s.pathDegraded = map[MonitorPair]PathDegradedRecord{}
		}
		s.pathDegraded[pair] = rec
		return nil
	}
	s.mu.Unlock()
	if !exists {
		return nil
	}
	if beforeWrite != nil {
		beforeWrite(pair)
	}
	if err := hot.PutPathDegradedRecord(pair, rec); err != nil {
		return err
	}
	s.mu.Lock()
	exists = s.monitorPairExistsLocked(pair)
	s.mu.Unlock()
	if exists {
		return nil
	}
	return hot.DeletePathDegradedRecord(pair)
}

// DeletePathDegradedRecord removes one pair's record; a missing one is not
// an error. With the hot store the bolt write runs outside the store lock.
func (s *Store) DeletePathDegradedRecord(pair MonitorPair) error {
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.DeletePathDegradedRecord(pair)
	}
	defer s.mu.Unlock()
	delete(s.pathDegraded, pair)
	return nil
}

// PathDegradedDurable reports whether records survive a restart (the hot
// store is on).
func (s *Store) PathDegradedDurable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runtimeBoltHot != nil
}

// deletePathDegradedMemLocked drops the in-memory records match selects,
// which is where they live without the hot store.
func (s *Store) deletePathDegradedMemLocked(match func(MonitorPair) bool) {
	for pair := range s.pathDegraded {
		if match(pair) {
			delete(s.pathDegraded, pair)
		}
	}
}

func (bs *BoltStateStore) PathDegradedRecords() (map[MonitorPair]PathDegradedRecord, error) {
	out := map[MonitorPair]PathDegradedRecord{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketMonPathDegraded)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			key, err := stringFromBoltKey(k)
			if err != nil {
				return nil
			}
			monitorID, nodeID, ok := splitMonitorPairKey(key)
			if !ok {
				return nil
			}
			var rec PathDegradedRecord
			if err := decodeRecordValue(boltBucketMonPathDegraded, key, v, &rec); err != nil {
				return err
			}
			out[MonitorPair{MonitorID: monitorID, NodeID: nodeID}] = rec
			return nil
		})
	})
	return out, err
}

func (bs *BoltStateStore) PutPathDegradedRecord(pair MonitorPair, rec PathDegradedRecord) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(boltBucketMonPathDegraded); err != nil {
			return err
		}
		return putRecord(tx, boltBucketMonPathDegraded, monitorPairKey(pair.MonitorID, pair.NodeID), rec)
	})
}

func (bs *BoltStateStore) DeletePathDegradedRecord(pair MonitorPair) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return deleteRecord(tx, boltBucketMonPathDegraded, monitorPairKey(pair.MonitorID, pair.NodeID))
	})
}

// deletePathDegradedForNodeTx removes every record whose node is nodeID. The
// bucket holds a record per degraded pair, a handful, so a scan is cheap.
func deletePathDegradedForNodeTx(tx *bolt.Tx, nodeID string) error {
	b := tx.Bucket(boltBucketMonPathDegraded)
	if b == nil {
		return nil
	}
	var keys [][]byte
	if err := b.ForEach(func(k, _ []byte) error {
		key, err := stringFromBoltKey(k)
		if err != nil {
			return nil
		}
		if _, owner, ok := splitMonitorPairKey(key); ok && owner == nodeID {
			keys = append(keys, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// MonitorBaseline is one pair's one-hour buckets over a baseline window,
// merged (Merged), and how many of them hold a countable run (Hours).
type MonitorBaseline struct {
	Merged MonitorRollup
	Hours  int
}

// MonitorRollupBaselines merges each pair's one-hour buckets whose start lies
// in [from, to) into one bucket and counts the buckets with a run, in one
// read. It is the degraded evaluator's hourly read: like
// MonitorRollupSummaries it runs in one bolt read transaction outside the
// store lock, seeks once per pair and decodes into one reused scratch
// record, so 600 paths' week costs a fraction of returning every bucket
// (MonitorRollups). A pair with no bucket in the window has no entry. from
// and to are aligned to the hour first.
func (s *Store) MonitorRollupBaselines(pairs []MonitorPair, from, to time.Time) (map[MonitorPair]MonitorBaseline, error) {
	from, to = from.UTC().Truncate(MonitorRollupCoarse), to.UTC().Truncate(MonitorRollupCoarse)
	if hot := s.hotForMonitorRead(); hot != nil {
		return hot.MonitorRollupBaselines(pairs, from, to)
	}
	defer s.mu.Unlock()
	out := map[MonitorPair]MonitorBaseline{}
	for _, pair := range pairs {
		var base MonitorBaseline
		for _, b := range RollupMonitorResults(s.jsonPairRowsLocked(pair), MonitorRollupCoarse, from, to) {
			if b.N > 0 {
				base.Hours++
			}
			base.Merged.Merge(b)
		}
		if base.Hours > 0 {
			out[pair] = base
		}
	}
	return out, nil
}

func (bs *BoltStateStore) MonitorRollupBaselines(pairs []MonitorPair, from, to time.Time) (map[MonitorPair]MonitorBaseline, error) {
	out := make(map[MonitorPair]MonitorBaseline, len(pairs))
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketMonRollupCoarse)
		if b == nil {
			return nil
		}
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
			first, err := boltStringKey(monitorResultKey(pair.MonitorID, pair.NodeID, from))
			if err != nil {
				return err
			}
			var base MonitorBaseline
			for k, v := c.Seek(first); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				if bytes.Compare(instantOfRowKey(k), toInstant) >= 0 {
					break
				}
				clear(scratch.H)
				h := scratch.H
				scratch = MonitorRollup{H: h}
				if err := json.Unmarshal(v, &scratch); err != nil {
					return fmt.Errorf("decode %s value: %w", boltBucketMonRollupCoarse, err)
				}
				if scratch.N > 0 {
					base.Hours++
				}
				base.Merged.Merge(scratch)
			}
			if base.Hours > 0 {
				out[pair] = base
			}
		}
		return nil
	})
	return out, err
}
