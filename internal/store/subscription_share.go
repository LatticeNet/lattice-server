package store

import (
	"errors"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// UpsertSubscriptionShare writes a share. Like proxy users, shares go to the
// record-level hot store when it is enabled rather than through a full rewrite of
// the state file.
func (s *Store) UpsertSubscriptionShare(share model.SubscriptionShare) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Pathless stores are explicitly ephemeral test/runtime views. Any disk-backed
	// store must have a real cipher before accepting bearer material.
	if s.path != "" && share.Token != "" && (s.cipher == nil || !s.cipher.Enabled()) {
		return errors.New("subscription share token requires an enabled cipher")
	}
	s.ensureMaps()
	now := time.Now().UTC()
	share.UpdatedAt = now
	if share.CreatedAt.IsZero() {
		share.CreatedAt = now
	}
	if share.SchemaVersion == 0 {
		share.SchemaVersion = model.SubscriptionShareSchemaVersion
	}
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.UpsertSubscriptionShare(share); err != nil {
			return err
		}
		s.state.SubscriptionShares[share.ID] = share
		return nil
	}
	staged := s.state
	staged.SubscriptionShares = make(map[string]model.SubscriptionShare, len(s.state.SubscriptionShares)+1)
	for id, current := range s.state.SubscriptionShares {
		staged.SubscriptionShares[id] = current
	}
	staged.SubscriptionShares[share.ID] = share
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}

// SubscriptionShare returns a share by id.
func (s *Store) SubscriptionShare(id string) (model.SubscriptionShare, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	share, ok := s.state.SubscriptionShares[id]
	return share, ok
}

// SubscriptionShareByToken resolves a share by its exact token. It is the only
// lookup the public endpoint performs. The comparison is whole-string on purpose:
// a prefix or substring match would turn a partially guessed token into a working
// one.
func (s *Store) SubscriptionShareByToken(token string) (model.SubscriptionShare, bool) {
	if token == "" {
		return model.SubscriptionShare{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, share := range s.state.SubscriptionShares {
		if share.Token == token {
			return share, true
		}
	}
	return model.SubscriptionShare{}, false
}

// SubscriptionShares returns every share sorted by creation time, then id, so the
// order is stable across calls and across processes.
func (s *Store) SubscriptionShares() []model.SubscriptionShare {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.SubscriptionShare, 0, len(s.state.SubscriptionShares))
	for _, share := range s.state.SubscriptionShares {
		out = append(out, share)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// DeleteSubscriptionShare removes a share, which immediately stops serving its
// URL.
func (s *Store) DeleteSubscriptionShare(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.DeleteSubscriptionShare(id); err != nil {
			return err
		}
		delete(s.state.SubscriptionShares, id)
		return nil
	}
	staged := s.state
	staged.SubscriptionShares = make(map[string]model.SubscriptionShare, len(s.state.SubscriptionShares))
	for currentID, current := range s.state.SubscriptionShares {
		if currentID != id {
			staged.SubscriptionShares[currentID] = current
		}
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}
