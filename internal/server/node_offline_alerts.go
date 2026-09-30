package server

import (
	"fmt"
	"sort"
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
	// Laptops and machines that sleep go offline by design.
	// yagni: a reserved tag, not a per-node alert policy. The ceiling is one
	// on/off word per node; a policy with per-node delays is the upgrade if an
	// operator needs more than that.
	nodeQuietOfflineTag = "no-offline-alert"
)

// nodeOfflineAlerts is the in-memory half of node.offline: which offline spell
// each node was alerted for, and recoveries of alerted spells waiting for the
// next sweep. It is not persisted. After a restart, a spell that was already
// longer than the alert delay when this process started stays silent, and the
// recovery of a spell the previous process alerted sends nothing.
type nodeOfflineAlerts struct {
	mu sync.Mutex
	// since is when this process began watching. Silence before it was not
	// observed here, so it is not counted toward the delay.
	since time.Time
	// alerted maps a node id to the LastSeen of the spell it was alerted for.
	// LastSeen does not move while a node is silent, so it names the spell.
	alerted   map[string]time.Time
	recovered []nodeLivenessChange
}

// nodeLivenessChange is one line of a node.offline or node.online message.
type nodeLivenessChange struct {
	id, name string
	// span is how long the node has been silent (offline) or was silent
	// (online).
	span     time.Duration
	lastSeen time.Time
}

func (a *nodeOfflineAlerts) start(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.since = now
}

// noteNodeOnline queues a node.online line when the spell that just ended was
// alerted. A spell that never alerted ends silently, which is what keeps brief
// gaps off the phone in both directions.
func (s *Server) noteNodeOnline(nodeID string, now time.Time) {
	name := s.nodeDisplayName(nodeID)
	a := &s.nodeAlerts
	a.mu.Lock()
	defer a.mu.Unlock()
	lastSeen, ok := a.alerted[nodeID]
	if !ok {
		return
	}
	delete(a.alerted, nodeID)
	a.recovered = append(a.recovered, nodeLivenessChange{id: nodeID, name: name, span: now.Sub(lastSeen), lastSeen: lastSeen})
}

// notifyNodeLiveness sends node.offline for nodes silent past
// nodeOfflineAlertAfter and node.online for alerted nodes that came back since
// the previous sweep. Each kind is one message per sweep, so a network blip on
// the control plane's side cannot page once per node.
func (s *Server) notifyNodeLiveness(now time.Time) {
	nodes := s.store.Nodes()
	a := &s.nodeAlerts
	a.mu.Lock()
	if a.alerted == nil {
		a.alerted = map[string]time.Time{}
	}
	present := make(map[string]bool, len(nodes))
	var down []nodeLivenessChange
	for _, n := range nodes {
		present[n.ID] = true
		if n.Online || n.LastSeen.IsZero() || nodeQuietOffline(n) {
			continue
		}
		if !a.since.IsZero() && n.LastSeen.Before(a.since.Add(-nodeOfflineAlertAfter)) {
			// Already silent past the delay when this process started. The
			// previous process had the spell; alerting it here would repeat
			// on every restart for a node that is simply gone.
			continue
		}
		silentFrom := n.LastSeen
		if silentFrom.Before(a.since) {
			silentFrom = a.since
		}
		if now.Sub(silentFrom) < nodeOfflineAlertAfter {
			continue
		}
		if spell, ok := a.alerted[n.ID]; ok && spell.Equal(n.LastSeen) {
			continue
		}
		a.alerted[n.ID] = n.LastSeen
		down = append(down, nodeLivenessChange{id: n.ID, name: nodeLabel(n), span: now.Sub(n.LastSeen), lastSeen: n.LastSeen})
	}
	for nodeID := range a.alerted {
		if !present[nodeID] {
			delete(a.alerted, nodeID)
		}
	}
	up := a.recovered
	a.recovered = nil
	a.mu.Unlock()

	if len(down) > 0 {
		title, body := nodeOfflineMessage(down)
		s.emitNotifyTyped(EventNodeOffline, title, body)
	}
	if len(up) > 0 {
		title, body := nodeOnlineMessage(up)
		s.emitNotifyTyped(EventNodeOnline, title, body)
	}
}

func nodeQuietOffline(n model.Node) bool {
	for _, tag := range n.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), nodeQuietOfflineTag) {
			return true
		}
	}
	return false
}

func nodeLabel(n model.Node) string {
	if name := strings.TrimSpace(n.Name); name != "" {
		return name
	}
	return n.ID
}

func nodeOfflineMessage(down []nodeLivenessChange) (string, string) {
	sortLivenessChanges(down)
	if len(down) == 1 {
		d := down[0]
		return "Lattice node offline: " + d.name,
			fmt.Sprintf("%s (%s) has not reported for %s. Last heartbeat %s.", d.name, d.id, livenessSpan(d.span), d.lastSeen.UTC().Format(time.RFC3339))
	}
	lines := make([]string, len(down))
	for i, d := range down {
		lines[i] = fmt.Sprintf("%s: no report for %s", d.name, livenessSpan(d.span))
	}
	return fmt.Sprintf("Lattice node offline digest: %d nodes", len(down)), strings.Join(lines, "\n")
}

func nodeOnlineMessage(up []nodeLivenessChange) (string, string) {
	sortLivenessChanges(up)
	if len(up) == 1 {
		u := up[0]
		return "Lattice node online: " + u.name,
			fmt.Sprintf("%s (%s) is reporting again after %s offline.", u.name, u.id, livenessSpan(u.span))
	}
	lines := make([]string, len(up))
	for i, u := range up {
		lines[i] = fmt.Sprintf("%s: back after %s", u.name, livenessSpan(u.span))
	}
	return fmt.Sprintf("Lattice node online digest: %d nodes", len(up)), strings.Join(lines, "\n")
}

func sortLivenessChanges(changes []nodeLivenessChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].name != changes[j].name {
			return changes[i].name < changes[j].name
		}
		return changes[i].id < changes[j].id
	})
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
