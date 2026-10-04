package server

import (
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
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
// One gap remains, and it is the agent's to close. On-box discovery reads
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
