package store

import (
	bolt "go.etcd.io/bbolt"
)

// The outbox buckets (notify_outbox.go). They are record-level only: not in
// boltStateBuckets, never part of State, created on the first write.
var (
	boltBucketNotifyDeliveries    = []byte("notify_deliveries")
	boltBucketNotifyChannelHealth = []byte("notify_channel_health")
	boltBucketNotifyDigestQueue   = []byte("notify_digest_queue")
)

// LoadNotifyOutbox reads the three outbox buckets. A missing bucket reads as
// empty.
func (bs *BoltStateStore) LoadNotifyOutbox() ([]NotifyDelivery, []NotifyChannelHealth, []NotifyDigestLine, error) {
	var (
		rows   []NotifyDelivery
		health []NotifyChannelHealth
		digest []NotifyDigestLine
	)
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		if err := forEachNotifyRecord(tx, boltBucketNotifyDeliveries, func(d NotifyDelivery) { rows = append(rows, d) }); err != nil {
			return err
		}
		if err := forEachNotifyRecord(tx, boltBucketNotifyChannelHealth, func(h NotifyChannelHealth) { health = append(health, h) }); err != nil {
			return err
		}
		return forEachNotifyRecord(tx, boltBucketNotifyDigestQueue, func(l NotifyDigestLine) { digest = append(digest, l) })
	})
	return rows, health, digest, err
}

func forEachNotifyRecord[T any](tx *bolt.Tx, bucket []byte, visit func(T)) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	return b.ForEach(func(k, v []byte) error {
		var rec T
		if err := decodeRecordValue(bucket, string(k), v, &rec); err != nil {
			return err
		}
		visit(rec)
		return nil
	})
}

// WriteNotifyOutbox applies one batch of outbox changes in one transaction.
func (bs *BoltStateStore) WriteNotifyOutbox(w notifyOutboxWrite) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for _, bucket := range [][]byte{boltBucketNotifyDeliveries, boltBucketNotifyChannelHealth, boltBucketNotifyDigestQueue} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		for _, d := range w.delRows {
			if err := deleteRecord(tx, boltBucketNotifyDeliveries, notifyDeliveryKey(d)); err != nil {
				return err
			}
		}
		for _, d := range w.putRows {
			if err := putRecord(tx, boltBucketNotifyDeliveries, notifyDeliveryKey(d), d); err != nil {
				return err
			}
		}
		for _, id := range w.delHealth {
			if err := deleteRecord(tx, boltBucketNotifyChannelHealth, id); err != nil {
				return err
			}
		}
		for _, h := range w.putHealth {
			if err := putRecord(tx, boltBucketNotifyChannelHealth, h.ChannelID, h); err != nil {
				return err
			}
		}
		for _, key := range w.delDigest {
			if err := deleteRecord(tx, boltBucketNotifyDigestQueue, key); err != nil {
				return err
			}
		}
		for _, l := range w.putDigest {
			if err := putRecord(tx, boltBucketNotifyDigestQueue, l.Key, l); err != nil {
				return err
			}
		}
		return nil
	})
}
