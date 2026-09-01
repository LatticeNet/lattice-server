package store

import (
	"errors"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// SingBoxLiveness is the durable service-liveness record for one node
// (design-19): the latest probe the agent reported, the state the server
// derived from it, and the transition bookkeeping that notification
// debouncing needs. It is persisted, unlike the inventory mirror, so a
// multi-day outage survives a server restart and can be reported after the
// fact.
type SingBoxLiveness struct {
	NodeID  string               `json:"node_id"`
	Runtime model.SingBoxRuntime `json:"runtime"`
	// State is running | down | restarting | unknown.
	State      string    `json:"state"`
	StateSince time.Time `json:"state_since"`
	// ProblemSince is set when the state leaves running for down/restarting
	// and cleared only by running again: a probe outage in the middle of an
	// incident must not reset the alert clock.
	ProblemSince time.Time `json:"problem_since,omitempty"`
	// NotifiedDownAt is when the down notification for the current problem
	// episode fired; zero when it has not. Cleared on recovery.
	NotifiedDownAt time.Time `json:"notified_down_at,omitempty"`
	ReceivedAt     time.Time `json:"received_at"`
}

// UpsertSingBoxLiveness stores one node's liveness record and returns the
// previous one. The caller (the ingest path) owns state derivation and
// transition logic; this method owns durability only.
func (s *Store) UpsertSingBoxLiveness(rec SingBoxLiveness) (SingBoxLiveness, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	rec.NodeID = strings.TrimSpace(rec.NodeID)
	if rec.NodeID == "" {
		return SingBoxLiveness{}, false, errors.New("node_id is required")
	}
	rec.ReceivedAt = rec.ReceivedAt.UTC()
	prev, hadPrev := s.state.SingBoxLiveness[rec.NodeID]
	next := make(map[string]SingBoxLiveness, len(s.state.SingBoxLiveness)+1)
	for nodeID, existing := range s.state.SingBoxLiveness {
		next[nodeID] = existing
	}
	next[rec.NodeID] = rec
	staged := s.state
	staged.SingBoxLiveness = next
	if committed, err := s.persistState(s.jsonPersistStateFrom(staged)); !committed {
		return SingBoxLiveness{}, false, err
	}
	s.state.SingBoxLiveness = next
	return prev, hadPrev, nil
}

// SingBoxLivenessRecord returns one node's liveness record.
func (s *Store) SingBoxLivenessRecord(nodeID string) (SingBoxLiveness, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	rec, ok := s.state.SingBoxLiveness[nodeID]
	return rec, ok
}

// SingBoxLivenessAll returns a copy of every node's liveness record.
func (s *Store) SingBoxLivenessAll() map[string]SingBoxLiveness {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	out := make(map[string]SingBoxLiveness, len(s.state.SingBoxLiveness))
	for nodeID, rec := range s.state.SingBoxLiveness {
		out[nodeID] = rec
	}
	return out
}
