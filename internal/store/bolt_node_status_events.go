package store

import (
	"bytes"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AppendNodeStatusEvents is the bolt half of appendNodeStatusEventsLocked:
// the rows and the per-id trim land in one transaction.
func (bs *BoltStateStore) AppendNodeStatusEvents(events []nodeStatusAppend) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return appendNodeStatusEventsTx(tx, events)
	})
}

func appendNodeStatusEventsTx(tx *bolt.Tx, events []nodeStatusAppend) error {
	for _, e := range events {
		if err := putRecord(tx, boltBucketNodeStatusEvents, nodeStatusEventKey(e.id, e.event.At), e.event); err != nil {
			return err
		}
		keys, err := nodeStatusEventKeys(tx, e.id)
		if err != nil {
			return err
		}
		for _, k := range keys[:max(0, len(keys)-maxNodeStatusEvents)] {
			if err := tx.Bucket(boltBucketNodeStatusEvents).Delete(k); err != nil {
				return err
			}
		}
	}
	return nil
}

// nodeStatusEventKeys is one id's raw keys, oldest first: the instant is
// fixed width, so bolt's key order is time order.
func nodeStatusEventKeys(tx *bolt.Tx, id string) ([][]byte, error) {
	b := tx.Bucket(boltBucketNodeStatusEvents)
	if b == nil {
		return nil, nil
	}
	prefix, err := usageDayPrefix(id)
	if err != nil {
		return nil, err
	}
	var keys [][]byte
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		keys = append(keys, append([]byte(nil), k...))
	}
	return keys, nil
}

func (bs *BoltStateStore) NodeStatusEvents(id string) ([]NodeStatusEvent, error) {
	out := []NodeStatusEvent{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketNodeStatusEvents)
		if b == nil {
			return nil
		}
		prefix, err := usageDayPrefix(id)
		if err != nil {
			return err
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			key, err := stringFromBoltKey(k)
			if err != nil {
				return err
			}
			var ev NodeStatusEvent
			if err := decodeRecordValue(boltBucketNodeStatusEvents, key, v, &ev); err != nil {
				return err
			}
			out = append(out, ev)
		}
		return nil
	})
	return out, err
}

// PruneNodeStatusEvents deletes every row older than the cutoff. The stale
// keys are found in a read transaction first: the sweep calls this every
// tick, and a write transaction with nothing to delete would still fsync.
func (bs *BoltStateStore) PruneNodeStatusEvents(before time.Time) (int, error) {
	cutoff := before.UTC().Format(nodeStatusEventLayout)
	var stale [][]byte
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketNodeStatusEvents)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			key, err := stringFromBoltKey(k)
			if err != nil {
				return err
			}
			if _, at, ok := splitUsageDayKey(key); ok && at < cutoff {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		})
	})
	if err != nil || len(stale) == 0 {
		return 0, err
	}
	err = bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketNodeStatusEvents)
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return len(stale), err
}

// NewestNodeStatusEvent is the instant of the newest row across every id.
// Keys sort by id first, so this is one walk of the bucket, once per start.
func (bs *BoltStateStore) NewestNodeStatusEvent() (time.Time, error) {
	newest := ""
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		b := tx.Bucket(boltBucketNodeStatusEvents)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			key, err := stringFromBoltKey(k)
			if err != nil {
				return err
			}
			if _, at, ok := splitUsageDayKey(key); ok && at > newest {
				newest = at
			}
			return nil
		})
	})
	if err != nil {
		return time.Time{}, err
	}
	return parseNodeStatusInstant(newest)
}

// SeedNodeStatusEvents copies JSON-side rows into bolt when the hot store is
// first enabled; a row bolt already holds wins, as with SeedUsageDays.
func (bs *BoltStateStore) SeedNodeStatusEvents(rows map[string]NodeStatusEvent) error {
	if len(rows) == 0 {
		return nil
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for key, row := range rows {
			var existing NodeStatusEvent
			found, err := getRecord(tx, boltBucketNodeStatusEvents, key, &existing)
			if err != nil {
				return err
			}
			if found {
				continue
			}
			if err := putRecord(tx, boltBucketNodeStatusEvents, key, row); err != nil {
				return err
			}
		}
		return nil
	})
}
