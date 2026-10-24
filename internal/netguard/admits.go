package netguard

import (
	"slices"

	"github.com/LatticeNet/lattice-server/internal/network"
)

// Audience is who a service on the node must be reachable from.
type Audience struct {
	// Mesh selects the WireGuard range; otherwise the audience is every
	// source arriving on the public interface.
	Mesh bool
	// MeshInterfaces are the interfaces the node's WireGuard zone names, if
	// any. Traffic from the mesh arrives on them, so an accept or a drop on
	// one of them applies to the mesh audience.
	MeshInterfaces []string
}

// Admits reports whether the rendered chain, walked first match wins, accepts
// new inbound connections on protocol and port from the whole audience. It
// is the check a plan that does not write lattice_guard runs against the
// node's current NetGuard compile (design 32 D7): self-host DNS on a node
// NetGuard manages asks it about its listeners.
//
// Unlike managementPathOpen it is strict about scope: an accept counts only
// when it admits every source of the audience, so a rule for one peer does
// not make a public resolver reachable. An earlier drop decides when it can
// reach every packet the accept admits from the audience: it applies on the
// audience's interface or on any, and drops every source of the audience. A
// drop for one bad network leaves the port open to everyone else.
func Admits(plan network.NFTPlan, protocol string, port int, audience Audience) bool {
	if normalized, err := network.NormalizeNFTPlan(plan); err == nil {
		plan = normalized
	}
	chain := append([]network.NFTInputRule(nil), plan.InputRules...)
	for _, list := range []struct {
		ports    []int
		protocol string
		mesh     bool
	}{
		{plan.PublicTCP, network.NFTProtoTCP, false},
		{plan.PublicUDP, network.NFTProtoUDP, false},
		{plan.WireGuardTCP, network.NFTProtoTCP, true},
		{plan.WireGuardUDP, network.NFTProtoUDP, true},
	} {
		if len(list.ports) == 0 {
			continue
		}
		rule := network.NFTInputRule{Protocol: list.protocol, Ports: list.ports, Action: network.NFTActionAccept}
		if list.mesh {
			rule.SourceCIDRs = []string{plan.WireGuardCIDR}
		} else {
			rule.Interface = plan.InterfaceName
		}
		chain = append(chain, rule)
	}
	for _, rule := range chain {
		if !matchesPort(rule, protocol, port) || !reachesAudience(plan, rule, audience) {
			continue
		}
		if rule.Action != network.NFTActionAccept {
			// Every packet from the audience that gets this far is dropped.
			if coversAudience(plan, rule, audience) {
				return false
			}
			continue
		}
		if coversAudience(plan, rule, audience) {
			return true
		}
	}
	return false
}

// matchesPort reports whether a rule can match a new connection of protocol
// to port.
func matchesPort(rule network.NFTInputRule, protocol string, port int) bool {
	if rule.Protocol == network.NFTProtoAny {
		return true
	}
	return rule.Protocol == protocol && (len(rule.Ports) == 0 || slices.Contains(rule.Ports, port))
}

// onAudienceInterface reports whether a rule's interface constraint lets it
// see the audience's traffic.
func onAudienceInterface(plan network.NFTPlan, rule network.NFTInputRule, audience Audience) bool {
	if rule.Interface == "" {
		return true
	}
	if audience.Mesh {
		return slices.Contains(audience.MeshInterfaces, rule.Interface)
	}
	return rule.Interface == plan.InterfaceName
}

// reachesAudience reports whether a rule can match some packet from the
// audience: it sees the audience's interface, and its sources (if any)
// overlap the audience.
func reachesAudience(plan network.NFTPlan, rule network.NFTInputRule, audience Audience) bool {
	if !onAudienceInterface(plan, rule, audience) {
		return false
	}
	if len(rule.SourceCIDRs) == 0 || !audience.Mesh {
		return true
	}
	mesh, ok := parseSourcePrefix(plan.WireGuardCIDR)
	if !ok {
		return true
	}
	for _, raw := range rule.SourceCIDRs {
		if src, ok := parseSourcePrefix(raw); ok && src.Addr().Is4() == mesh.Addr().Is4() && (src.Contains(mesh.Addr()) || mesh.Contains(src.Addr())) {
			return true
		}
	}
	return false
}

// coversAudience reports whether a rule matches every source of the
// audience: any source on the public interface for public, the whole
// WireGuard range for mesh (by source range or by a mesh interface).
func coversAudience(plan network.NFTPlan, rule network.NFTInputRule, audience Audience) bool {
	if !onAudienceInterface(plan, rule, audience) {
		return false
	}
	if audience.Mesh {
		return len(rule.SourceCIDRs) == 0 || sourceWithinAny(plan.WireGuardCIDR, rule.SourceCIDRs)
	}
	return unrestrictedSources(rule.SourceCIDRs)
}

// unrestrictedSources reports whether a source list admits everyone: no list
// at all, or a /0, which is how an operator spells "everything" in a rule.
func unrestrictedSources(sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, raw := range sources {
		if prefix, ok := parseSourcePrefix(raw); ok && prefix.Bits() == 0 {
			return true
		}
	}
	return false
}
