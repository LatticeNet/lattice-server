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
//
// A record that differs from the stored one only in its clocks (received_at
// and the probe's probed_at) replaces it in memory without a write, until the
// copy on disk is reportClockPersistInterval old. Anything else, a state
// change, the incident bookkeeping, a restart counter or a probe error, is
// written before this returns, so a restart always resumes from the latest
// state, the open episode and whether it was already notified.
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
	if hadPrev && singBoxLivenessDurablyEqual(prev, rec) && !reportClockDue(s.livenessOnDisk, rec.NodeID, rec.ReceivedAt) {
		s.state.SingBoxLiveness[rec.NodeID] = rec
		return prev, true, nil
	}
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

// singBoxLivenessDurablyEqual compares two records with their clocks cleared.
// Every other field is state: PID, start time and executable digest change
// only when the process does, and the probe error is a condition, not a clock.
func singBoxLivenessDurablyEqual(a, b SingBoxLiveness) bool {
	ra, rb := a.Runtime, b.Runtime
	startedEqual := ra.StartedAt.Equal(rb.StartedAt)
	// Times are compared with Equal, never ==: a record read back from disk
	// and one built from a report can name the same instant differently.
	ra.StartedAt, rb.StartedAt = time.Time{}, time.Time{}
	ra.ProbedAt, rb.ProbedAt = time.Time{}, time.Time{}
	return a.NodeID == b.NodeID && ra == rb && startedEqual && a.State == b.State &&
		a.StateSince.Equal(b.StateSince) && a.ProblemSince.Equal(b.ProblemSince) &&
		a.NotifiedDownAt.Equal(b.NotifiedDownAt)
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
