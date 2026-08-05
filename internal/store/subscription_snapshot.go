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
	s.state.SubscriptionSnapshots[key] = snap
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.UpsertSubscriptionSnapshot(key, snap)
	}
	return s.Save()
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
	delete(s.state.SubscriptionSnapshots, key)
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.DeleteSubscriptionSnapshot(key)
	}
	return s.Save()
}
