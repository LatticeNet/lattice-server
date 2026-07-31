package store

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
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

// ErrGuardRealityNodeChanged is returned when the node authenticated by the
// handler no longer exists as the same immutable identity generation.
var ErrGuardRealityNodeChanged = errors.New("guard reality node identity changed")

// ErrGuardRealityDurabilityDegraded means the atomic rename committed the
// snapshot, but syncing the parent directory failed. Callers must treat the
// snapshot as accepted while surfacing the durability warning operationally.
var ErrGuardRealityDurabilityDegraded = errors.New("guard reality committed with degraded durability")

// UpsertGuardRealitySnapshot stores the latest normalized reality snapshot for
// a node. Same collected_at plus identical content is idempotent and does not
// rewrite received_at; same collected_at plus different content is a conflict.
func (s *Store) UpsertGuardRealitySnapshot(nodeIdentityUUID string, snapshot GuardRealitySnapshot) (GuardRealitySnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	snapshot = canonicalizeGuardRealitySnapshot(snapshot)
	snapshot.Reality.CollectedAt = snapshot.Reality.CollectedAt.UTC()
	snapshot.ReceivedAt = snapshot.ReceivedAt.UTC()
	if snapshot.Reality.NodeID == "" {
		return GuardRealitySnapshot{}, false, errors.New("node_id is required")
	}
	node, ok := s.state.Nodes[snapshot.Reality.NodeID]
	if !ok || strings.TrimSpace(node.LatticeIdentityUUID) != strings.TrimSpace(nodeIdentityUUID) {
		return GuardRealitySnapshot{}, false, ErrGuardRealityNodeChanged
	}
	if existing, ok := s.state.GuardRealitySnapshots[snapshot.Reality.NodeID]; ok {
		existing = canonicalizeGuardRealitySnapshot(existing)
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
	next := make(map[string]GuardRealitySnapshot, len(s.state.GuardRealitySnapshots)+1)
	for nodeID, existing := range s.state.GuardRealitySnapshots {
		next[nodeID] = existing
	}
	next[snapshot.Reality.NodeID] = snapshot
	staged := s.state
	staged.GuardRealitySnapshots = next
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if !committed {
		return GuardRealitySnapshot{}, false, err
	}
	s.state.GuardRealitySnapshots = next
	if err != nil {
		return cloneGuardRealitySnapshot(snapshot), true, fmt.Errorf("%w: %v", ErrGuardRealityDurabilityDegraded, err)
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

func canonicalizeGuardRealitySnapshot(snapshot GuardRealitySnapshot) GuardRealitySnapshot {
	snapshot = cloneGuardRealitySnapshot(snapshot)
	if len(snapshot.Reality.Listeners) == 0 {
		snapshot.Reality.Listeners = nil
	} else {
		sort.Slice(snapshot.Reality.Listeners, func(i, j int) bool {
			a, b := snapshot.Reality.Listeners[i], snapshot.Reality.Listeners[j]
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
			if a.Port != b.Port {
				return a.Port < b.Port
			}
			if a.Address != b.Address {
				return a.Address < b.Address
			}
			return a.Process < b.Process
		})
	}
	if len(snapshot.Reality.Interfaces) == 0 {
		snapshot.Reality.Interfaces = nil
	} else {
		for i := range snapshot.Reality.Interfaces {
			if len(snapshot.Reality.Interfaces[i].Addresses) == 0 {
				snapshot.Reality.Interfaces[i].Addresses = nil
			} else {
				sort.Strings(snapshot.Reality.Interfaces[i].Addresses)
			}
		}
		sort.Slice(snapshot.Reality.Interfaces, func(i, j int) bool {
			a, b := snapshot.Reality.Interfaces[i], snapshot.Reality.Interfaces[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.Up != b.Up {
				return !a.Up
			}
			return strings.Join(a.Addresses, "\x00") < strings.Join(b.Addresses, "\x00")
		})
	}
	if len(snapshot.Reality.ForeignTables) == 0 {
		snapshot.Reality.ForeignTables = nil
	} else {
		sort.Strings(snapshot.Reality.ForeignTables)
	}
	return snapshot
}
