package store

import (
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// MarkSubscriptionSnapshotsStale invalidates the durable snapshots of the
// named records of one plugin in one store transaction, keeping each
// last-good payload, as MarkPluginSubscriptionSnapshotsStale does for every
// snapshot of the plugin. A Sub-Store plan whose apply failed marks only the
// records of its fleet closure: the next access refetches them, which rolls a
// half-done promotion forward, while every other record keeps serving. A
// record with no snapshot is skipped.
func (s *Store) MarkSubscriptionSnapshotsStale(pluginID string, subscriptionIDs []string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	changed := make(map[string]model.SubscriptionSnapshot, len(subscriptionIDs))
	for _, id := range subscriptionIDs {
		key := model.SnapshotKey(pluginID, id)
		current, ok := s.state.SubscriptionSnapshots[key]
		if !ok {
			continue
		}
		current.Stale = true
		current.FetchError = "source_mutated"
		// An authority invalidation, not a provider failure: no retry
		// backoff, so the next access fetches at once.
		current.LastAttemptAt = time.Time{}
		changed[key] = current
	}
	if len(changed) == 0 {
		return true, nil
	}
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.UpsertSubscriptionSnapshots(changed); err != nil {
			return false, err
		}
		for key, snapshot := range changed {
			s.state.SubscriptionSnapshots[key] = snapshot
		}
		return true, nil
	}
	staged := s.state
	staged.SubscriptionSnapshots = make(map[string]model.SubscriptionSnapshot, len(s.state.SubscriptionSnapshots))
	for key, current := range s.state.SubscriptionSnapshots {
		if replacement, ok := changed[key]; ok {
			staged.SubscriptionSnapshots[key] = replacement
		} else {
			staged.SubscriptionSnapshots[key] = current
		}
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return committed, err
}
