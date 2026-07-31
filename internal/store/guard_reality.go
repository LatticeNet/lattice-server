package store

import (
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// GuardRealitySnapshot stores the server-accepted, normalized latest reality
// report for one node. It deliberately contains operational facts only: raw
// request bytes, bearer credentials, stderr, key material, and secrets are
// forbidden from this collection.
type GuardRealitySnapshot struct {
	Reality    model.GuardNodeReality `json:"reality"`
	ReceivedAt time.Time              `json:"received_at"`
}

// ErrGuardRealityStale is returned when a write would replace a newer snapshot
// or conflict with a different snapshot collected at the same instant.
var ErrGuardRealityStale = errors.New("guard reality snapshot is stale")

// UpsertGuardRealitySnapshot stores the latest normalized reality snapshot for
// a node. Same collected_at plus identical content is idempotent and does not
// rewrite received_at; same collected_at plus different content is a conflict.
func (s *Store) UpsertGuardRealitySnapshot(snapshot GuardRealitySnapshot) (GuardRealitySnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	snapshot = cloneGuardRealitySnapshot(snapshot)
	snapshot.Reality.CollectedAt = snapshot.Reality.CollectedAt.UTC()
	snapshot.ReceivedAt = snapshot.ReceivedAt.UTC()
	if snapshot.Reality.NodeID == "" {
		return GuardRealitySnapshot{}, false, errors.New("node_id is required")
	}
	if existing, ok := s.state.GuardRealitySnapshots[snapshot.Reality.NodeID]; ok {
		existing = cloneGuardRealitySnapshot(existing)
		existing.Reality.CollectedAt = existing.Reality.CollectedAt.UTC()
		existing.ReceivedAt = existing.ReceivedAt.UTC()
		switch {
		case snapshot.Reality.CollectedAt.Before(existing.Reality.CollectedAt):
			return existing, false, ErrGuardRealityStale
		case snapshot.Reality.CollectedAt.Equal(existing.Reality.CollectedAt):
			if reflect.DeepEqual(snapshot.Reality, existing.Reality) {
				return existing, false, nil
			}
			return existing, false, ErrGuardRealityStale
		}
	}
	s.state.GuardRealitySnapshots[snapshot.Reality.NodeID] = snapshot
	if err := s.Save(); err != nil {
		return GuardRealitySnapshot{}, false, err
	}
	return cloneGuardRealitySnapshot(snapshot), true, nil
}

// GuardRealitySnapshot returns a deep copy of one node's latest reality report.
func (s *Store) GuardRealitySnapshot(nodeID string) (GuardRealitySnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	snapshot, ok := s.state.GuardRealitySnapshots[nodeID]
	if !ok {
		return GuardRealitySnapshot{}, false
	}
	return cloneGuardRealitySnapshot(snapshot), true
}

// GuardRealitySnapshots returns all snapshots sorted by node id.
func (s *Store) GuardRealitySnapshots() []GuardRealitySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	out := make([]GuardRealitySnapshot, 0, len(s.state.GuardRealitySnapshots))
	for _, snapshot := range s.state.GuardRealitySnapshots {
		out = append(out, cloneGuardRealitySnapshot(snapshot))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Reality.NodeID < out[j].Reality.NodeID
	})
	return out
}

func cloneGuardRealitySnapshot(snapshot GuardRealitySnapshot) GuardRealitySnapshot {
	snapshot.Reality.Listeners = append([]model.GuardListener(nil), snapshot.Reality.Listeners...)
	if snapshot.Reality.Interfaces != nil {
		interfaces := make([]model.GuardInterface, len(snapshot.Reality.Interfaces))
		for i, iface := range snapshot.Reality.Interfaces {
			iface.Addresses = append([]string(nil), iface.Addresses...)
			interfaces[i] = iface
		}
		snapshot.Reality.Interfaces = interfaces
	}
	snapshot.Reality.ForeignTables = append([]string(nil), snapshot.Reality.ForeignTables...)
	return snapshot
}
