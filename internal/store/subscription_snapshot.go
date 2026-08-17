package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func validateCloneSubscriptionSnapshot(snap model.SubscriptionSnapshot) (model.SubscriptionSnapshot, error) {
	if strings.TrimSpace(snap.PluginID) == "" || strings.TrimSpace(snap.SubscriptionID) == "" {
		return model.SubscriptionSnapshot{}, errors.New("subscription snapshot identity is required")
	}
	if len(snap.Raw) > model.MaxSubscriptionRawBytes {
		return model.SubscriptionSnapshot{}, fmt.Errorf("subscription snapshot raw content exceeds %d bytes", model.MaxSubscriptionRawBytes)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return model.SubscriptionSnapshot{}, fmt.Errorf("encode subscription snapshot: %w", err)
	}
	var validated model.SubscriptionSnapshot
	if err := json.Unmarshal(raw, &validated); err != nil {
		return model.SubscriptionSnapshot{}, fmt.Errorf("validate subscription snapshot: %w", err)
	}
	return validated.Clone(), nil
}

func validateCloneSubscriptionSnapshots(in map[string]model.SubscriptionSnapshot) (map[string]model.SubscriptionSnapshot, error) {
	out := make(map[string]model.SubscriptionSnapshot, len(in))
	for key, snapshot := range in {
		validated, err := validateCloneSubscriptionSnapshot(snapshot)
		if err != nil {
			return nil, fmt.Errorf("subscription snapshot %q: %w", key, err)
		}
		if want := model.SnapshotKey(validated.PluginID, validated.SubscriptionID); key != want {
			return nil, fmt.Errorf("subscription snapshot key %q does not match identity %q", key, want)
		}
		out[key] = validated
	}
	return out, nil
}

// UpsertSubscriptionSnapshot writes the last good content for one subscription.
// It is durable rather than cached: it is what keeps clients served when a
// provider is unreachable.
func (s *Store) UpsertSubscriptionSnapshot(snap model.SubscriptionSnapshot) error {
	_, err := s.UpsertSubscriptionSnapshotWithCommit(snap)
	return err
}

// UpsertSubscriptionSnapshotWithCommit distinguishes a pre-commit failure from
// a committed rename whose parent-directory durability confirmation failed.
// Callers must publish the committed state to their own cache authority even
// when err reports degraded durability.
func (s *Store) UpsertSubscriptionSnapshotWithCommit(snap model.SubscriptionSnapshot) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Pathless stores are explicitly ephemeral test/runtime views. Any disk-backed
	// store must have a real cipher before accepting opaque provider credentials.
	if s.path != "" && snap.Raw != "" && (s.cipher == nil || !s.cipher.Enabled()) {
		return false, errors.New("subscription snapshot raw content requires an enabled cipher")
	}
	s.ensureMaps()
	if snap.SchemaVersion == 0 {
		snap.SchemaVersion = model.SubscriptionSnapshotSchemaVersion
	}
	if snap.FetchedAt.IsZero() {
		snap.FetchedAt = time.Now().UTC()
	}
	var err error
	snap, err = validateCloneSubscriptionSnapshot(snap)
	if err != nil {
		return false, err
	}
	key := model.SnapshotKey(snap.PluginID, snap.SubscriptionID)
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.UpsertSubscriptionSnapshot(key, snap); err != nil {
			return false, err
		}
		s.state.SubscriptionSnapshots[key] = snap
		return true, nil
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
	return committed, err
}

func (s *Store) SubscriptionSnapshot(pluginID, subscriptionID string) (model.SubscriptionSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.state.SubscriptionSnapshots[model.SnapshotKey(pluginID, subscriptionID)]
	if !ok {
		return model.SubscriptionSnapshot{}, false
	}
	return snap.Clone(), true
}

func (s *Store) SubscriptionSnapshots() []model.SubscriptionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.SubscriptionSnapshot, 0, len(s.state.SubscriptionSnapshots))
	for _, snap := range s.state.SubscriptionSnapshots {
		out = append(out, snap.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		return model.SnapshotKey(out[i].PluginID, out[i].SubscriptionID) < model.SnapshotKey(out[j].PluginID, out[j].SubscriptionID)
	})
	return out
}

// MarkPluginSubscriptionSnapshotsStale invalidates every durable snapshot
// owned by one plugin in one store transaction. It deliberately preserves the
// last-good payload and provenance; the next access must fetch again before the
// snapshot can become fresh authority.
func (s *Store) MarkPluginSubscriptionSnapshotsStale(pluginID string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	changed := make(map[string]model.SubscriptionSnapshot)
	for key, current := range s.state.SubscriptionSnapshots {
		if current.PluginID != pluginID {
			continue
		}
		current.Stale = true
		current.FetchError = "source_mutated"
		// This is an authority invalidation, not a provider failure. Leave the
		// retry timestamp empty so the next access immediately fetches the new
		// plugin state rather than observing the outage backoff interval.
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
