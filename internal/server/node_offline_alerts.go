package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Typed notification kinds for agent liveness, declared beside their emitter.
// Before these existed the sweep sent a title the classifier did not know, so
// every offline alert went out as "generic" and no operator rule routed it.
const (
	EventNodeOffline = "node.offline"
	EventNodeOnline  = "node.online"
)

const (
	// nodeOfflineAlertAfter is how long a node must stay silent, as this
	// process saw it, before node.offline notifies. The 90s liveness threshold
	// is right for the console, where a dead node should look dead within two
	// minutes, and wrong for a phone: of the 1,021 offline spells production
	// recorded between 2026-09-07 and 2026-09-30, 75% ended within five minutes.
	nodeOfflineAlertAfter = 10 * time.Minute
	// nodeQuietOfflineTag keeps a node out of node.offline and node.online.
	nodeQuietOfflineTag = "no-offline-alert"
	// nodeOfflineAfterTagPrefix sets a node's own delay, as
	// "offline-alert-after:3h" or ":45m". Machines that sleep or roam go
	// offline all the time; the operator still wants to hear when one stays
	// gone for hours. The silence is recorded either way (audit and status
	// history); only the page waits.
	// yagni: policy lives in tags, which the console already edits and both
	// store runtimes already persist. The ceiling is one delay per node with
	// no schedule; a stored per-node policy with its own editor is the
	// upgrade if that stops being enough.
	nodeOfflineAfterTagPrefix = "offline-alert-after:"
	minNodeOfflineAlertAfter  = 2 * time.Minute
	maxNodeOfflineAlertAfter  = 7 * 24 * time.Hour
)

// nodeOfflineAlerts is the state behind node.offline. Which spell paged is
// the node's node.offline incident (incidents.go), stored on the record-level
// path, so a page sent before a restart is still answered by node.online
// after it. What stays here is in memory: when this process began watching,
// and the disabled bookkeeping. A spell that was already longer than the
// alert delay when this process started stays silent: the process that saw it
// begin owned the page.
//
// An open incident owes its page until the sweep sends it, and the owed flag
// is stored with the record, so a process killed between the decision and the
// send pages after the restart. A process killed before the record was
// written decided nothing durable, and the new process pages the spell itself
// if it is still inside its window.
//
// mu orders a beat against the sweep: the sweep reads the fleet and opens
// incidents under it, and noteNodeOnline resolves under it, so a node that
// returns during a sweep is either online in the sweep's read or resolves the
// incident the sweep just opened.
type nodeOfflineAlerts struct {
	mu sync.Mutex
	// since is when this process began watching. Silence before it was not
	// observed here, so it is not counted toward the delay.
	since time.Time
	// disabled holds the nodes the last sweep saw disabled, and watchFrom
	// when a sweep first saw each of them enabled again. A disabled node's
	// token is refused, so its silence is the operator's doing and never
	// pages; once enabled, its silence counts from then, not from a LastSeen
	// that may be days old.
	disabled  map[string]bool
	watchFrom map[string]time.Time
}

func (a *nodeOfflineAlerts) start(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.since = now
}

// noteNodeOnline resolves the node's offline incident when the spell that
// just ended opened one. The recovery goes out with the next sweep, and only
// if the page did; a spell that never paged ends silently, which is what
// keeps brief gaps off the phone in both directions.
func (s *Server) noteNodeOnline(nodeID string, now time.Time) {
	a := &s.nodeAlerts
	a.mu.Lock()
	defer a.mu.Unlock()
	s.resolveNodeOffline(nodeID, s.nodeDisplayName(nodeID), now)
}

func (s *Server) resolveNodeOffline(nodeID, name string, now time.Time) {
	key := incidentKey(EventNodeOffline, nodeID, "")
	inc, ok := s.store.ActiveIncident(key)
	if !ok {
		return
	}
	span := now.Sub(inc.Since)
	s.resolveIncident(key, now, incidentMessage{
		title:  "Lattice node online: " + name,
		detail: fmt.Sprintf("%s (%s) is reporting again after %s offline.", name, nodeID, livenessSpan(span)),
		line:   fmt.Sprintf("%s: back after %s", name, livenessSpan(span)),
	})
}

// forgetNodeOfflineAlert drops a deleted node's alert state, loop health and
// trace collector status from memory. The store's delete cascade has already
// removed the node and its incidents.
func (s *Server) forgetNodeOfflineAlert(nodeID string) {
	a := &s.nodeAlerts
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.disabled, nodeID)
	delete(a.watchFrom, nodeID)
	s.forgetAgentHealth(nodeID)
	s.forgetTraceCollector(nodeID)
}

// notifyNodeLiveness opens node.offline incidents for nodes silent past
// their delay and settles any open one whose node is reporting. The sweep's
// incident pass then sends each kind as one message, so a network blip on
// the control plane's side cannot page once per node.
func (s *Server) notifyNodeLiveness(now time.Time) {
	a := &s.nodeAlerts
	// Read the fleet under a.mu; see nodeOfflineAlerts for why. Nothing
	// takes a.mu while holding a store lock or incidentMu, so the order a.mu,
	// incidentMu, store is safe.
	a.mu.Lock()
	defer a.mu.Unlock()
	nodes := s.store.Nodes()
	if a.disabled == nil {
		a.disabled = map[string]bool{}
		a.watchFrom = map[string]time.Time{}
	}
	present := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		present[n.ID] = true
		if n.Disabled {
			// Disabling refuses the token and leaves Online alone, so the
			// sweep flips the node offline like any silent one. That silence
			// is the operator's own action, never a page. A spell paged
			// before the node was disabled stays owed its node.online.
			a.disabled[n.ID] = true
			delete(a.watchFrom, n.ID)
			continue
		}
		if a.disabled[n.ID] {
			delete(a.disabled, n.ID)
			a.watchFrom[n.ID] = now
		}
		if n.Online {
			delete(a.watchFrom, n.ID)
			// A reporting node has no open offline incident. The beat that
			// brought it back resolves it; this catches a resolve that never
			// ran (a record written while the beat raced a restart).
			s.resolveNodeOffline(n.ID, nodeLabel(n), now)
			continue
		}
		delay, pages := nodeOfflineDelay(n)
		if n.LastSeen.IsZero() || !pages {
			continue
		}
		// After a crash a LastSeen this process has not confirmed may trail
		// the node's real last beat by the store's slack, so "silent before
		// start" is judged with that much margin. Without it a node that died
		// just before the crash looked long gone and never paged. A spell the
		// previous process did page is still owned by its incident record.
		//
		// A node that went silent before an outage longer than its delay is
		// still skipped, and never pages: that is the existing "silent before
		// start" rule, which counts only silence this process saw. The slack
		// narrows it by the lag; it does not remove it.
		slack := s.store.NodeLastSeenSlack(n.ID)
		if !a.since.IsZero() && n.LastSeen.Before(a.since.Add(-delay-slack)) {
			// Already silent past the delay when this process started. The
			// previous process had the spell; alerting it here would repeat
			// on every restart for a node that is simply gone.
			continue
		}
		silentFrom := n.LastSeen
		if silentFrom.Before(a.since) {
			silentFrom = a.since
		}
		if from, ok := a.watchFrom[n.ID]; ok && silentFrom.Before(from) {
			silentFrom = from
		}
		if now.Sub(silentFrom) < delay {
			continue
		}
		name := nodeLabel(n)
		s.openIncident(incidentSignal{
			kind: EventNodeOffline, nodeID: n.ID, subject: name, since: n.LastSeen,
			sortKey: name + "\x00" + n.ID,
			msg:     nodeOfflineIncidentMessage(n, now.Sub(n.LastSeen), n.LastSeen),
		}, now)
	}
	for nodeID := range a.disabled {
		if !present[nodeID] {
			delete(a.disabled, nodeID)
		}
	}
	for nodeID := range a.watchFrom {
		if !present[nodeID] {
			delete(a.watchFrom, nodeID)
		}
	}
}

func nodeOfflineIncidentMessage(n model.Node, span time.Duration, lastSeen time.Time) incidentMessage {
	name := nodeLabel(n)
	return incidentMessage{
		title:  "Lattice node offline: " + name,
		detail: fmt.Sprintf("%s (%s) has not reported for %s. Last heartbeat %s.", name, n.ID, livenessSpan(span), lastSeen.UTC().Format(time.RFC3339)),
		line:   fmt.Sprintf("%s: no report for %s", name, livenessSpan(span)),
	}
}

// nodeOfflineDelay is how long n must stay silent before node.offline, and
// false when it never pages. The quiet tag wins over any delay; of several
// valid delay tags the longest wins; a tag that does not parse is ignored
// here and shown as invalid by the console, so a typo falls back to the
// default rather than to silence.
func nodeOfflineDelay(n model.Node) (time.Duration, bool) {
	var custom time.Duration
	for _, tag := range n.Tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == nodeQuietOfflineTag {
			return 0, false
		}
		if d, ok := parseNodeOfflineAfterTag(tag); ok && d > custom {
			custom = d
		}
	}
	if custom > 0 {
		return custom, true
	}
	return nodeOfflineAlertAfter, true
}

// parseNodeOfflineAfterTag reads "offline-alert-after:<digits><m|h>" within
// minNodeOfflineAlertAfter and maxNodeOfflineAlertAfter.
func parseNodeOfflineAfterTag(tag string) (time.Duration, bool) {
	value, ok := strings.CutPrefix(tag, nodeOfflineAfterTagPrefix)
	if !ok || len(value) < 2 || len(value) > 6 {
		return 0, false
	}
	digits, unit := value[:len(value)-1], value[len(value)-1]
	var n int64
	for _, r := range digits {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int64(r-'0')
	}
	var d time.Duration
	switch unit {
	case 'm':
		d = time.Duration(n) * time.Minute
	case 'h':
		d = time.Duration(n) * time.Hour
	default:
		return 0, false
	}
	if d < minNodeOfflineAlertAfter || d > maxNodeOfflineAlertAfter {
		return 0, false
	}
	return d, true
}

func nodeLabel(n model.Node) string {
	if name := strings.TrimSpace(n.Name); name != "" {
		return name
	}
	return n.ID
}

// livenessSpan reads as minutes under two hours and hours after that; the
// message is for a phone, not a log.
func livenessSpan(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	if d < 2*time.Hour {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%d h", int(d/time.Hour))
	}
	return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
}
