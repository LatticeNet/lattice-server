package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	bolt "go.etcd.io/bbolt"
)

// ApplyProxyUsage is the bolt half of Store.ApplyProxyUsage: the snapshot, the
// user projections, the profile and the day rows land in one transaction.
func (bs *BoltStateStore) ApplyProxyUsage(update ProxyUsageUpdate) error {
	if update.empty() {
		return nil
	}
	now := time.Now().UTC()
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for _, user := range update.Users {
			user = normalizeProxyUserForStore(user, now)
			enc, err := encryptProxyUserRecord(user.ID, user, bs.cipher)
			if err != nil {
				return err
			}
			if err := putRecord(tx, boltBucketProxyUsers, user.ID, enc); err != nil {
				return err
			}
		}
		if update.Profile != nil {
			normalized := normalizeProxyNodeProfileForStore(*update.Profile, now)
			if err := putRecord(tx, boltBucketProxyProfiles, normalized.NodeID, normalized); err != nil {
				return err
			}
		}
		if update.Snapshot != nil {
			normalized := normalizeProxyUsageSnapshotForStore(*update.Snapshot, now)
			if err := putRecord(tx, boltBucketProxyUsage, normalized.NodeID, normalized); err != nil {
				return err
			}
		}
		if update.DayNode != nil {
			key := UsageDayKey(update.DayNode.NodeID, update.DayNode.Day)
			var row UsageDayNode
			if _, err := getRecord(tx, boltBucketUsageDayNode, key, &row); err != nil {
				return err
			}
			addUsageDayNode(&row, *update.DayNode)
			if err := putRecord(tx, boltBucketUsageDayNode, key, row); err != nil {
				return err
			}
		}
		for _, delta := range update.DayUsers {
			key := UsageDayKey(delta.UserID, delta.Day)
			var row UsageDayUser
			if _, err := getRecord(tx, boltBucketUsageDayUser, key, &row); err != nil {
				return err
			}
			addUsageDayUser(&row, delta)
			if err := putRecord(tx, boltBucketUsageDayUser, key, row); err != nil {
				return err
			}
		}
		return nil
	})
}

// ApplyProxyUsageUpdate keeps the pre-rollup signature for callers that carry
// no day rows.
func (bs *BoltStateStore) ApplyProxyUsageUpdate(users []model.ProxyUser, profile *model.ProxyNodeProfile, snapshot *model.ProxyUsageSnapshot) error {
	return bs.ApplyProxyUsage(ProxyUsageUpdate{Users: users, Profile: profile, Snapshot: snapshot})
}

// usageDayPrefix is the encoded key prefix shared by every day of one id. Keys
// are JSON strings, so the prefix is the encoded "<id>/" with its closing quote
// removed; json.Marshal escapes the id the same way in both places.
func usageDayPrefix(id string) ([]byte, error) {
	enc, err := boltStringKey(id + "/")
	if err != nil {
		return nil, err
	}
	return enc[:len(enc)-1], nil
}

// scanUsageDays visits the records of one id whose day lies in [from, to],
// oldest first. It seeks straight to <id>/<from> and stops at the first key
// past the id, so the cost is the number of days asked for, not the bucket.
func scanUsageDays[T any](tx *bolt.Tx, bucket []byte, id, from, to string, visit func(day string, value T)) error {
	b := tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	prefix, err := usageDayPrefix(id)
	if err != nil {
		return err
	}
	start, err := boltStringKey(UsageDayKey(id, from))
	if err != nil {
		return err
	}
	c := b.Cursor()
	for k, v := c.Seek(start); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		key, err := stringFromBoltKey(k)
		if err != nil {
			return err
		}
		_, day, ok := splitUsageDayKey(key)
		if !ok {
			continue
		}
		if day > to {
			break
		}
		var value T
		if err := decodeRecordValue(bucket, key, v, &value); err != nil {
			return err
		}
		visit(day, value)
	}
	return nil
}

func decodeRecordValue[T any](bucket []byte, key string, data []byte, out *T) error {
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode %s[%q]: %w", bucket, key, err)
	}
	return nil
}

func (bs *BoltStateStore) UsageDayNodeRows(nodeID, from, to string) ([]UsageDayNode, error) {
	out := []UsageDayNode{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return scanUsageDays(tx, boltBucketUsageDayNode, nodeID, from, to, func(_ string, row UsageDayNode) {
			out = append(out, row)
		})
	})
	return out, err
}

func (bs *BoltStateStore) UsageDayUserRows(userID, from, to string) ([]UsageDayUser, error) {
	out := []UsageDayUser{}
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		return scanUsageDays(tx, boltBucketUsageDayUser, userID, from, to, func(_ string, row UsageDayUser) {
			out = append(out, row)
		})
	})
	return out, err
}

// PruneUsageDays deletes every row in both buckets whose day is older than
// the cutoff. One full walk of two buckets, once per day roll.
func (bs *BoltStateStore) PruneUsageDays(before string) (int, error) {
	pruned := 0
	err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for _, bucket := range [][]byte{boltBucketUsageDayNode, boltBucketUsageDayUser} {
			b := tx.Bucket(bucket)
			if b == nil {
				continue
			}
			var stale [][]byte
			err := b.ForEach(func(k, _ []byte) error {
				key, err := stringFromBoltKey(k)
				if err != nil {
					return err
				}
				if _, day, ok := splitUsageDayKey(key); ok && day < before {
					stale = append(stale, append([]byte(nil), k...))
				}
				return nil
			})
			if err != nil {
				return err
			}
			for _, k := range stale {
				if err := b.Delete(k); err != nil {
					return err
				}
				pruned++
			}
		}
		return nil
	})
	return pruned, err
}

// SeedUsageDays copies JSON-side rows into bolt when the hot store is first
// enabled. A row bolt already holds wins: bolt is authoritative from then on
// and the JSON copy is whatever was last flushed before the switch.
func (bs *BoltStateStore) SeedUsageDays(nodes map[string]UsageDayNode, users map[string]UsageDayUser) error {
	if len(nodes) == 0 && len(users) == 0 {
		return nil
	}
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for key, row := range nodes {
			var existing UsageDayNode
			found, err := getRecord(tx, boltBucketUsageDayNode, key, &existing)
			if err != nil {
				return err
			}
			if found {
				continue
			}
			if err := putRecord(tx, boltBucketUsageDayNode, key, row); err != nil {
				return err
			}
		}
		for key, row := range users {
			var existing UsageDayUser
			found, err := getRecord(tx, boltBucketUsageDayUser, key, &existing)
			if err != nil {
				return err
			}
			if found {
				continue
			}
			if err := putRecord(tx, boltBucketUsageDayUser, key, row); err != nil {
				return err
			}
		}
		return nil
	})
}
