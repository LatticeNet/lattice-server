package store

import (
	"strings"
	"time"
)

// Node offline alert bookkeeping: which offline spell node.offline paged for,
// keyed by node id, valued by the node's LastSeen at the page. LastSeen does
// not move while a node is silent, so it names the spell.
//
// It is persisted so a page sent before a control plane restart is still
// answered by node.online after it. It changes only when a page goes out, a
// paged node comes back, or a paged node is removed, so the write it costs is
// rare: the same small-state-on-change shape as the sing-box liveness record,
// never a write per sweep.

// NodeOfflineAlerts returns a copy of the paged spells.
func (s *Store) NodeOfflineAlerts() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	out := make(map[string]time.Time, len(s.state.NodeOfflineAlerts))
	for nodeID, at := range s.state.NodeOfflineAlerts {
		out[nodeID] = at
	}
	return out
}

// SetNodeOfflineAlerts replaces the paged spells. It writes only when next
// differs from what is stored, and installs next in memory only once the write
// committed, so a failed write leaves memory and disk agreeing.
func (s *Store) SetNodeOfflineAlerts(next map[string]time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	staged := make(map[string]time.Time, len(next))
	for nodeID, at := range next {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			continue
		}
		staged[nodeID] = at.UTC()
	}
	if nodeOfflineAlertsEqual(s.state.NodeOfflineAlerts, staged) {
		return nil
	}
	st := s.state
	st.NodeOfflineAlerts = staged
	if committed, err := s.persistState(s.jsonPersistStateFrom(st)); !committed {
		return err
	}
	s.state.NodeOfflineAlerts = staged
	return nil
}

func nodeOfflineAlertsEqual(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for nodeID, at := range a {
		other, ok := b[nodeID]
		if !ok || !other.Equal(at) {
			return false
		}
	}
	return true
}
