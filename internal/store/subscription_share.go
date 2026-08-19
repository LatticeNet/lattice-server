package store

import (
	"crypto/subtle"
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
// lookup the public endpoint performs, and that endpoint is unauthenticated, so
// this is the one comparison in the product an anonymous caller can drive.
//
// The comparison is whole-string on purpose: a prefix or substring match would
// turn a partially guessed token into a working one. It is also constant-time,
// and the scan does not stop at the first hit. Returning early leaks, through
// timing, both how far a candidate token matched and where the matching share
// sat in the iteration; neither is information the caller is entitled to. The
// cost is a full pass over a map that holds one entry on a real deployment.
//
// A duplicate token fails closed. It should be unreachable, since tokens are
// generated from a CSPRNG, but "unreachable" plus "silently serves whichever
// share the map happened to yield first" is a bad pair: Go randomises map
// iteration, so the same token would serve different subscriptions on different
// requests. Refusing is the only answer that is the same every time.
func (s *Store) SubscriptionShareByToken(token string) (model.SubscriptionShare, bool) {
	if token == "" {
		return model.SubscriptionShare{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var found model.SubscriptionShare
	matches := 0
	for _, share := range s.state.SubscriptionShares {
		if subtle.ConstantTimeCompare([]byte(share.Token), []byte(token)) == 1 {
			found = share
			matches++
		}
	}
	if matches != 1 {
		return model.SubscriptionShare{}, false
	}
	return found, true
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
