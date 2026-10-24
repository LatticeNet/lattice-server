package netguard

import (
	"slices"

	"github.com/LatticeNet/lattice-server/internal/network"
)

// Audience is who a service on the node must be reachable from.
type Audience int

const (
	// AudiencePublic is every source arriving on the public interface.
	AudiencePublic Audience = iota
	// AudienceMesh is the WireGuard range.
	AudienceMesh
)

// Admits reports whether the rendered chain, walked first match wins, accepts
// new inbound connections on protocol and port from the whole audience. It
// is the check a plan that does not write lattice_guard runs against the
// node's current NetGuard compile (design 32 D7): self-host DNS on a node
// NetGuard manages asks it about its listeners.
//
// Unlike managementPathOpen it is strict about scope: an accept counts only
// when it admits every source of the audience, so a rule for one peer does
// not make a public resolver reachable. It shares managementPathOpen's view
// of drops: an earlier drop decides only when it matches everything the
// accept matches, so an operator's deny for one bad network leaves the port
// open to everyone else.
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
	var drops []network.NFTInputRule
	for _, rule := range chain {
		if !matchesPort(rule, protocol, port) {
			continue
		}
		if rule.Action != network.NFTActionAccept {
			drops = append(drops, rule)
			continue
		}
		if !coversAudience(plan, rule, audience) {
			continue
		}
		if _, shadowed := shadowingDrop(drops, rule); shadowed {
			continue
		}
		return true
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

// coversAudience reports whether an accept admits every source of the
// audience: any source on the public interface (or on any interface) for
// public, the whole WireGuard range for mesh.
func coversAudience(plan network.NFTPlan, rule network.NFTInputRule, audience Audience) bool {
	switch audience {
	case AudiencePublic:
		return (rule.Interface == "" || rule.Interface == plan.InterfaceName) && len(rule.SourceCIDRs) == 0
	case AudienceMesh:
		return rule.Interface == "" && (len(rule.SourceCIDRs) == 0 || sourceWithinAny(plan.WireGuardCIDR, rule.SourceCIDRs))
	}
	return false
}
