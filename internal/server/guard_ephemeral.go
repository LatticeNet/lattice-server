package server

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// A proxy node's reality report lists the core's client sockets as listeners.
// The agent collects with `ss -tulpn`, and -l prints every unconnected UDP
// socket, so each QUIC, hysteria, TUIC or DNS dial sing-box makes shows up as
// a UDP "listener" on a port the kernel picked from net.ipv4.ip_local_port_range.
// They come and go between reports. In production on 2026-10-04 they were the
// only difference between six consecutive state.json writes, 176 of the 209
// writes in one hour were guard reality reports, and every one of those
// sockets counted in the NetGuard overview as a port open with no rule.
//
// The server splits them out of the facts when a report arrives. A socket is
// an ephemeral client socket only when all of these hold:
//
//   - it is UDP;
//   - its port is inside the kernel's ephemeral range;
//   - sing-box owns it;
//   - the node's sing-box inventory is fresh and complete, and no line in it,
//     nor any inbound Lattice renders onto the node, listens on or is
//     published at that port.
//
// Everything else stays a fact, so a hysteria inbound on 50000 is still a
// listener, and still an exposure when no rule covers it.
//
// The rule is limited to sing-box on purpose. Telling an inbound from a client
// socket takes a list of the inbounds, and sing-box is the only core whose
// inbounds the server can enumerate. A real UDP service on an ephemeral port
// run by xray or a standalone hysteria server would be indistinguishable from
// a client socket, and a rule that ignored the owner would also take kernel
// WireGuard sockets (no process, and 51820 is inside the range) and tailscaled
// on 41641. Any condition the server cannot check leaves the socket a fact:
// noise on a node it cannot vouch for is better than a hidden service.
//
// The owner name is a heuristic for telling noise from services, not a trust
// boundary. It is the task name ss prints, which any local process can set,
// so a process that calls itself sing-box and binds UDP inside the range on a
// node whose inventory vouches is read as a client socket: it leaves the
// listeners, the exposure counts and the missing-allow suggestions. Two
// things bound that. Every such socket is still served in ephemeral_sockets,
// and one that stays bound across reports for ephemeralPersistAfter is
// audited once per episode as netguard.ephemeral_socket_persistent (see
// ephemeralSocketTracker). Most client sockets close long before that; a
// long-lived QUIC or hysteria outbound to an upstream also trips it, once,
// and a listener waiting for connections has to. Closing the gap needs the agent to report the
// owner's executable path or uid with each socket, so the server can check
// the socket belongs to the sing-box the inventory describes.
//
// One more gap is also the agent's to close. On-box discovery reads
// `sb --json list` and the config's inbounds, not sing-box endpoints, so a
// WireGuard or Tailscale endpoint configured on sing-box by hand, with a
// listen_port inside the range, reads as a client socket here. Lattice
// renders no endpoints and runs WireGuard in the kernel, which this rule never
// touches, and such a socket is still served in ephemeral_sockets rather than
// dropped. The fix is for discovery to report endpoint listen ports with the
// inventory.

// The Linux default for net.ipv4.ip_local_port_range. Agents do not report
// the node's own range yet; a node configured with a narrower one only keeps
// more of its sockets as facts, and one with a wider range keeps the sockets
// outside this one.
const (
	ephemeralPortFirst = 32768
	ephemeralPortLast  = 60999
)

// singBoxProcess is the process name ss prints for sing-box, which is what
// the agent reports as a listener's owner.
const singBoxProcess = "sing-box"

// splitEphemeralSockets returns the listeners that are facts and the ones
// that are sing-box client sockets, in their original order. A node whose
// inventory cannot vouch for its inbounds gets every listener back as a fact.
func (s *Server) splitEphemeralSockets(nodeID string, listeners []model.GuardListener, now time.Time) (facts, ephemeral []model.GuardListener) {
	if !hasEphemeralCandidate(listeners) {
		return listeners, nil
	}
	inbound, ok := s.singBoxInboundPorts(nodeID, now)
	if !ok {
		return listeners, nil
	}
	facts = make([]model.GuardListener, 0, len(listeners))
	for _, listener := range listeners {
		if isEphemeralCandidate(listener) && !inbound[listener.Port] {
			ephemeral = append(ephemeral, listener)
			continue
		}
		facts = append(facts, listener)
	}
	return facts, ephemeral
}

func hasEphemeralCandidate(listeners []model.GuardListener) bool {
	for _, listener := range listeners {
		if isEphemeralCandidate(listener) {
			return true
		}
	}
	return false
}

// isEphemeralCandidate is every condition but the inventory one.
func isEphemeralCandidate(listener model.GuardListener) bool {
	return listener.Protocol == model.NetProtoUDP &&
		listener.Port >= ephemeralPortFirst && listener.Port <= ephemeralPortLast &&
		listener.Process == singBoxProcess
}

// singBoxInboundPorts returns the ports the node's sing-box inbounds listen on
// or are published at, and false when the server cannot claim to know them:
// no inventory, a failed discovery, one older than nodeOfflineThreshold, or a
// line whose port does not read as a single port. Inbounds the central proxy
// model renders onto the node are added too, so a line the on-box discovery
// misses is still covered when Lattice put it there.
func (s *Server) singBoxInboundPorts(nodeID string, now time.Time) (map[int]bool, bool) {
	inv, ok := s.singBoxInventory(nodeID)
	if !ok || inv.Status != "ok" || inv.At.IsZero() || now.Sub(inv.At) > nodeOfflineThreshold {
		return nil, false
	}
	ports := make(map[int]bool, 2*len(inv.Nodes))
	for _, line := range inv.Nodes {
		port, ok := inventoryPort(line.Port)
		if !ok {
			return nil, false
		}
		ports[port] = true
		if strings.TrimSpace(line.PublicPort) == "" {
			continue
		}
		public, ok := inventoryPort(line.PublicPort)
		if !ok {
			return nil, false
		}
		ports[public] = true
	}
	if profile, ok := s.store.ProxyNodeProfile(nodeID); ok {
		for _, inboundID := range profile.InboundIDs {
			if inbound, ok := s.store.ProxyInbound(inboundID); ok && inbound.Port > 0 {
				ports[inbound.Port] = true
			}
		}
	}
	return ports, true
}

func inventoryPort(raw string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// ephemeralPersistAfter is how long a socket read as a sing-box client socket
// may stay bound, report after report, before it is audited.
const ephemeralPersistAfter = 30 * time.Minute

// ephemeralTrackCap bounds how many client sockets are followed per node. A
// report may list thousands; past the cap a new socket is not followed until
// one that is followed goes away. Sockets already followed keep their place.
const ephemeralTrackCap = 256

// auditActionEphemeralSocketPersistent is recorded once per persistence
// episode of one client socket.
const auditActionEphemeralSocketPersistent = "netguard.ephemeral_socket_persistent"

type ephemeralSocketKey struct {
	protocol string
	port     int
	address  string
}

type ephemeralSocketEpisode struct {
	firstSeen time.Time
	audited   bool
}

// persistentEphemeralSocket is a client socket whose episode just crossed
// ephemeralPersistAfter.
type persistentEphemeralSocket struct {
	socket    model.GuardListener
	firstSeen time.Time
}

// ephemeralSocketTracker remembers, per node and in memory only, since when
// each socket read as a client socket has been listed in consecutive reports.
// A report that does not list a socket as a client socket ends its episode,
// whether the socket closed or the report read it as a fact. A restart starts
// every episode again. Nothing here is persisted, so following a socket never
// writes state.
type ephemeralSocketTracker struct {
	mu    sync.Mutex
	nodes map[string]map[ephemeralSocketKey]ephemeralSocketEpisode
}

// observe takes one accepted report's client sockets for a node and returns
// the ones that have now been bound for ephemeralPersistAfter, each once per
// episode, in report order.
func (t *ephemeralSocketTracker) observe(nodeID string, sockets []model.GuardListener, now time.Time) []persistentEphemeralSocket {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev := t.nodes[nodeID]
	if len(sockets) == 0 {
		if prev != nil {
			delete(t.nodes, nodeID)
		}
		return nil
	}
	next := make(map[ephemeralSocketKey]ephemeralSocketEpisode, min(len(sockets), ephemeralTrackCap))
	// Sockets already followed first, so a burst of new ones cannot push a
	// long episode out at the cap; then new ones while there is room.
	for _, socket := range sockets {
		key := ephemeralSocketKey{protocol: socket.Protocol, port: socket.Port, address: socket.Address}
		if episode, ok := prev[key]; ok {
			next[key] = episode
		}
	}
	for _, socket := range sockets {
		key := ephemeralSocketKey{protocol: socket.Protocol, port: socket.Port, address: socket.Address}
		if _, ok := next[key]; !ok && len(next) < ephemeralTrackCap {
			next[key] = ephemeralSocketEpisode{firstSeen: now}
		}
	}
	var due []persistentEphemeralSocket
	for _, socket := range sockets {
		key := ephemeralSocketKey{protocol: socket.Protocol, port: socket.Port, address: socket.Address}
		episode, ok := next[key]
		if !ok || episode.audited || now.Sub(episode.firstSeen) < ephemeralPersistAfter {
			continue
		}
		episode.audited = true
		next[key] = episode
		due = append(due, persistentEphemeralSocket{socket: socket, firstSeen: episode.firstSeen})
	}
	if t.nodes == nil {
		t.nodes = map[string]map[ephemeralSocketKey]ephemeralSocketEpisode{}
	}
	t.nodes[nodeID] = next
	return due
}

// forget drops a node's episodes (called on delete).
func (t *ephemeralSocketTracker) forget(nodeID string) {
	t.mu.Lock()
	delete(t.nodes, nodeID)
	t.mu.Unlock()
}

// auditPersistentEphemeralSockets follows the client sockets of an accepted
// report and records one audit event for each socket that has stayed bound
// for ephemeralPersistAfter. With the runtime bolt store, which production
// runs, an audit append does not rewrite state.json.
func (s *Server) auditPersistentEphemeralSockets(r *http.Request, nodeID string, sockets []model.GuardListener, now time.Time) {
	for _, due := range s.ephemeralSockets.observe(nodeID, sockets, now) {
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			Action:   auditActionEphemeralSocketPersistent,
			Decision: "observe",
			NodeID:   nodeID,
			Metadata: map[string]string{
				"protocol":   due.socket.Protocol,
				"port":       strconv.Itoa(due.socket.Port),
				"address":    due.socket.Address,
				"process":    due.socket.Process,
				"first_seen": due.firstSeen.UTC().Format(time.RFC3339),
			},
		})
	}
}
