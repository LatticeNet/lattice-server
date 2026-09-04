package store

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Node status history: one record per transition of a node's Online flag,
// keyed "<id>/<instant>" in node_status_events. The bucket takes the usage-day
// placement: with the hot store on it lives only in bolt and is read with a
// prefix seek, so the JSON state is never rewritten with it.
//
// Exactly two hooks write. The beat that turns Online false to true
// (UpdateMetrics, and the hello path through AppendNodeStatusEvent) and the
// liveness sweep that turns it true to false (MarkStaleNodesOffline). Nothing
// samples: a node that never flaps has no rows, and its state over a window
// is read off the node record by the history endpoint.
//
// The control plane records its own runs under NodeStatusServerID: an offline
// row at the last instant the previous process is known to have been alive
// and an online row at start. A stopped control plane observes nothing, so
// the endpoint renders that gap as unknown rather than as every node going
// down; the sweep at start then flips whatever really died.
//
// Bounds: rows older than NodeStatusEventRetention go on the sweep tick, and
// each id keeps at most maxNodeStatusEvents rows (the maxMonitorResults
// pattern). Thirty-three nodes at the observed flap rate write about thirty
// rows a day, well under both.
const (
	NodeStatusEventRetention = 30 * 24 * time.Hour
	maxNodeStatusEvents      = 500
	// nodeStatusEventLayout is fixed width so keys sort as instants.
	nodeStatusEventLayout = "2006-01-02T15:04:05.000000000Z"

	// NodeStatusServerID keys the control plane's own rows. Node ids come from
	// id.New and never start with an underscore.
	NodeStatusServerID = "_server"

	NodeStatusOnline  = "online"
	NodeStatusOffline = "offline"

	NodeStatusCauseBeat          = "beat"
	NodeStatusCauseLivenessSweep = "liveness_sweep"
	NodeStatusCauseServerStart   = "server_start"
	NodeStatusCauseServerStop    = "server_stop"
)

// NodeStatusEvent is one transition. To is NodeStatusOnline or
// NodeStatusOffline; Cause names the hook that wrote it.
type NodeStatusEvent struct {
	At    time.Time `json:"at"`
	To    string    `json:"to"`
	Cause string    `json:"cause"`
}

// nodeStatusAppend pairs a transition with its id for the batched append the
// sweep needs.
type nodeStatusAppend struct {
	id    string
	event NodeStatusEvent
}

func nodeStatusEventKey(id string, at time.Time) string {
	return id + "/" + at.UTC().Format(nodeStatusEventLayout)
}

func validNodeStatusID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\x00") {
		return fmt.Errorf("invalid node status id %q", id)
	}
	return nil
}

// AppendNodeStatusEvent records one transition for a caller outside the two
// store-owned hooks; the hello path uses it for the beat that also registers
// the node.
func (s *Store) AppendNodeStatusEvent(id string, ev NodeStatusEvent) error {
	if err := validNodeStatusID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.appendNodeStatusEventsLocked([]nodeStatusAppend{{id: id, event: ev}}); err != nil {
		return err
	}
	if s.runtimeBoltHot != nil {
		return nil
	}
	return s.Save()
}

// appendNodeStatusEventsLocked writes the rows and trims each id to the cap.
// With the hot store on the rows land in bolt; otherwise they go into the
// state and the caller persists, since every hook already saves for the node
// flag it just flipped.
func (s *Store) appendNodeStatusEventsLocked(events []nodeStatusAppend) error {
	if len(events) == 0 {
		return nil
	}
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.AppendNodeStatusEvents(events)
	}
	for _, e := range events {
		s.state.NodeStatusEvents[nodeStatusEventKey(e.id, e.event.At)] = e.event
		keys := s.nodeStatusEventKeysLocked(e.id)
		for _, key := range keys[:max(0, len(keys)-maxNodeStatusEvents)] {
			delete(s.state.NodeStatusEvents, key)
		}
	}
	return nil
}

// nodeStatusEventKeysLocked is one id's keys, oldest first.
func (s *Store) nodeStatusEventKeysLocked(id string) []string {
	var keys []string
	for key := range s.state.NodeStatusEvents {
		if owner, _, ok := splitUsageDayKey(key); ok && owner == id {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// NodeStatusEvents returns one id's rows, oldest first.
func (s *Store) NodeStatusEvents(id string) ([]NodeStatusEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.NodeStatusEvents(id)
	}
	keys := s.nodeStatusEventKeysLocked(id)
	out := make([]NodeStatusEvent, 0, len(keys))
	for _, key := range keys {
		out = append(out, s.state.NodeStatusEvents[key])
	}
	return out, nil
}

// PruneNodeStatusEvents deletes every row older than the cutoff and reports
// how many went. Called on the liveness sweep tick.
func (s *Store) PruneNodeStatusEvents(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.PruneNodeStatusEvents(before)
	}
	cutoff := before.UTC().Format(nodeStatusEventLayout)
	pruned := 0
	for key := range s.state.NodeStatusEvents {
		if _, at, ok := splitUsageDayKey(key); ok && at < cutoff {
			delete(s.state.NodeStatusEvents, key)
			pruned++
		}
	}
	if pruned == 0 {
		return 0, nil
	}
	return pruned, s.Save()
}

// RecordServerStart writes the control plane's own transition pair. The
// previous process left no stop mark, so its last known instant is the newest
// heartbeat or transition it persisted. LastSeen is persisted at most every
// five minutes per node, so on a fleet of one that instant can trail the real
// stop by up to that much; the error only widens the unknown gap.
func (s *Store) RecordServerStart(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()
	var stopped time.Time
	for _, n := range s.state.Nodes {
		if n.LastSeen.After(stopped) {
			stopped = n.LastSeen
		}
	}
	newest, err := s.newestNodeStatusEventLocked()
	if err != nil {
		return err
	}
	// The newest row may be the previous start itself, when nothing beat in
	// that whole run. A stop at that same instant would share its key, so the
	// gap opens one tick after the last thing the previous process wrote.
	if !newest.IsZero() && !newest.Before(stopped) {
		stopped = newest.Add(time.Nanosecond)
	}
	var events []nodeStatusAppend
	if !stopped.IsZero() && stopped.Before(now) {
		events = append(events, nodeStatusAppend{id: NodeStatusServerID, event: NodeStatusEvent{At: stopped, To: NodeStatusOffline, Cause: NodeStatusCauseServerStop}})
	}
	events = append(events, nodeStatusAppend{id: NodeStatusServerID, event: NodeStatusEvent{At: now, To: NodeStatusOnline, Cause: NodeStatusCauseServerStart}})
	if err := s.appendNodeStatusEventsLocked(events); err != nil {
		return err
	}
	if s.runtimeBoltHot != nil {
		return nil
	}
	return s.Save()
}

// newestNodeStatusEventLocked is the instant of the newest row across every
// id, zero when there are none. One walk of the keys, once per start.
func (s *Store) newestNodeStatusEventLocked() (time.Time, error) {
	if s.runtimeBoltHot != nil {
		return s.runtimeBoltHot.NewestNodeStatusEvent()
	}
	newest := ""
	for key := range s.state.NodeStatusEvents {
		if _, at, ok := splitUsageDayKey(key); ok && at > newest {
			newest = at
		}
	}
	return parseNodeStatusInstant(newest)
}

func parseNodeStatusInstant(at string) (time.Time, error) {
	if at == "" {
		return time.Time{}, nil
	}
	return time.Parse(nodeStatusEventLayout, at)
}
