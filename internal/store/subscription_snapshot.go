package store

import (
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// UpsertSubscriptionSnapshot writes the last good content for one subscription.
// It is durable rather than cached: it is what keeps clients served when a
// provider is unreachable.
func (s *Store) UpsertSubscriptionSnapshot(snap model.SubscriptionSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	if snap.SchemaVersion == 0 {
		snap.SchemaVersion = model.SubscriptionSnapshotSchemaVersion
	}
	if snap.FetchedAt.IsZero() {
		snap.FetchedAt = time.Now().UTC()
	}
	key := model.SnapshotKey(snap.PluginID, snap.SubscriptionID)
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.UpsertSubscriptionSnapshot(key, snap); err != nil {
			return err
		}
		s.state.SubscriptionSnapshots[key] = snap
		return nil
	}
	staged := s.state
	staged.SubscriptionSnapshots = make(map[string]model.SubscriptionSnapshot, len(s.state.SubscriptionSnapshots)+1)
	for id, current := range s.state.SubscriptionSnapshots {
		staged.SubscriptionSnapshots[id] = current
	}
	staged.SubscriptionSnapshots[key] = snap
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}

func (s *Store) SubscriptionSnapshot(pluginID, subscriptionID string) (model.SubscriptionSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.state.SubscriptionSnapshots[model.SnapshotKey(pluginID, subscriptionID)]
	return snap, ok
}

func (s *Store) SubscriptionSnapshots() []model.SubscriptionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.SubscriptionSnapshot, 0, len(s.state.SubscriptionSnapshots))
	for _, snap := range s.state.SubscriptionSnapshots {
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool {
		return model.SnapshotKey(out[i].PluginID, out[i].SubscriptionID) < model.SnapshotKey(out[j].PluginID, out[j].SubscriptionID)
	})
	return out
}

func (s *Store) DeleteSubscriptionSnapshot(pluginID, subscriptionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	key := model.SnapshotKey(pluginID, subscriptionID)
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.DeleteSubscriptionSnapshot(key); err != nil {
			return err
		}
		delete(s.state.SubscriptionSnapshots, key)
		return nil
	}
	staged := s.state
	staged.SubscriptionSnapshots = make(map[string]model.SubscriptionSnapshot, len(s.state.SubscriptionSnapshots))
	for id, current := range s.state.SubscriptionSnapshots {
		if id != key {
			staged.SubscriptionSnapshots[id] = current
		}
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}
