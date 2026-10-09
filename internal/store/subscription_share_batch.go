package store

import (
	"errors"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	bolt "go.etcd.io/bbolt"
)

// UpsertSubscriptionShares writes several shares as one commit: one bolt
// transaction on the record-level hot store, or one state rewrite without
// it. Reordering every share of a large fleet is one write rather than one
// per share, and a failed write leaves every share as it was.
func (s *Store) UpsertSubscriptionShares(shares []model.SubscriptionShare) error {
	if len(shares) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path != "" && (s.cipher == nil || !s.cipher.Enabled()) {
		for _, share := range shares {
			if share.Token != "" {
				return errors.New("subscription share token requires an enabled cipher")
			}
		}
	}
	s.ensureMaps()
	now := time.Now().UTC()
	prepared := make([]model.SubscriptionShare, 0, len(shares))
	for _, share := range shares {
		if share.ID == "" {
			return errors.New("subscription share id is required")
		}
		share.UpdatedAt = now
		if share.CreatedAt.IsZero() {
			share.CreatedAt = now
		}
		if share.SchemaVersion == 0 {
			share.SchemaVersion = model.SubscriptionShareSchemaVersion
		}
		prepared = append(prepared, share)
	}
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.UpsertSubscriptionShares(prepared); err != nil {
			return err
		}
		for _, share := range prepared {
			s.state.SubscriptionShares[share.ID] = share
		}
		s.invalidateShareTokenIndexLocked()
		return nil
	}
	staged := s.state
	staged.SubscriptionShares = make(map[string]model.SubscriptionShare, len(s.state.SubscriptionShares)+len(prepared))
	for id, current := range s.state.SubscriptionShares {
		staged.SubscriptionShares[id] = current
	}
	for _, share := range prepared {
		staged.SubscriptionShares[share.ID] = share
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
		s.invalidateShareTokenIndexLocked()
	}
	return err
}

// UpsertSubscriptionShares writes several share records in one transaction,
// each token sealed as UpsertSubscriptionShare seals it. The caller has set
// the timestamps.
func (bs *BoltStateStore) UpsertSubscriptionShares(shares []model.SubscriptionShare) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for _, share := range shares {
			enc, err := encryptSubscriptionShareRecord(share.ID, share, bs.cipher)
			if err != nil {
				return err
			}
			if err := putRecord(tx, boltBucketSubShares, share.ID, enc); err != nil {
				return err
			}
		}
		return nil
	})
}
