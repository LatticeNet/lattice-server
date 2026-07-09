// Package netguard implements the design-13 security-group firewall plane.
// This G1 slice is read-only: it materializes the design-13 view (security
// group + node binding + resolved builtin zones) of a node's legacy NFTInputs
// baseline without mutating the store or any apply path. The G2 slice adds the
// compiler with a byte-parity gate against network.GenerateNFTPlan before the
// legacy path retires.
package netguard

import (
	"sort"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	// LegacyGroupPrefix namespaces the node-private security groups derived
	// from legacy NFTInputs baselines (design-13 §7.1).
	LegacyGroupPrefix = "sg-legacy-"

	defaultInterface     = "eth0"
	defaultWireGuardCIDR = "10.66.0.0/24"
)

// PortRanges compresses a port list into sorted, deduplicated inclusive
// ranges: [9009,9010,9011,9013] becomes 9009-9011 and 9013. Out-of-range
// values are dropped rather than widened (fail-closed).
func PortRanges(ports []int) []model.GuardPortRange {
	valid := make([]int, 0, len(ports))
	for _, p := range ports {
		if p >= 1 && p <= 65535 {
			valid = append(valid, p)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	sort.Ints(valid)
	out := []model.GuardPortRange{{From: valid[0], To: valid[0]}}
	for _, p := range valid[1:] {
		last := &out[len(out)-1]
		switch {
		case p == last.To: // duplicate
		case p == last.To+1:
			last.To = p
		default:
			out = append(out, model.GuardPortRange{From: p, To: p})
		}
	}
	return out
}

// LegacyView is the read-only design-13 rendering of one node's legacy
// NFTInputs baseline.
type LegacyView struct {
	Group   model.SecurityGroup
	Binding model.NodeGuardBinding
	Zones   []model.GuardZone
}

// LegacyBaseline converts a legacy NFTInputs record into the design-13 shape:
// one node-private security group whose rules reference the builtin public and
// wireguard zones, a binding attaching that group, and the node-resolved zone
// definitions. Semantics are preserved exactly: legacy "wireguard ports" were
// port-scoped source-CIDR allows, so the wireguard zone appears as a rule
// remote, never as a trusted zone in Binding.ZoneIDs. Managed is false: the
// node stays observe-only until an operator explicitly adopts it (G2).
func LegacyBaseline(inputs model.NFTInputs) LegacyView {
	iface := inputs.InterfaceName
	if iface == "" {
		iface = defaultInterface
	}
	wgCIDR := inputs.WireGuardCIDR
	if wgCIDR == "" {
		wgCIDR = defaultWireGuardCIDR
	}

	publicRemote := model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic}
	wgRemote := model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZoneWireGuard}

	rules := make([]model.GuardRule, 0, 4)
	appendRule := func(id, proto, comment string, ports []int, remote model.NetEndpoint) {
		ranges := PortRanges(ports)
		if len(ranges) == 0 {
			return
		}
		rules = append(rules, model.GuardRule{
			ID:        id,
			Comment:   comment,
			Action:    model.NetRuleAllow,
			Direction: model.NetDirIngress,
			Protocol:  proto,
			Ports:     ranges,
			Remote:    remote,
		})
	}
	appendRule("legacy-public-tcp", model.NetProtoTCP, "public lattice tcp ports", inputs.PublicTCP, publicRemote)
	appendRule("legacy-public-udp", model.NetProtoUDP, "public lattice udp ports", inputs.PublicUDP, publicRemote)
	appendRule("legacy-wg-tcp", model.NetProtoTCP, "wg tcp services", inputs.WireGuardTCP, wgRemote)
	appendRule("legacy-wg-udp", model.NetProtoUDP, "wg udp services", inputs.WireGuardUDP, wgRemote)

	groupID := LegacyGroupPrefix + inputs.NodeID
	group := model.SecurityGroup{
		ID:          groupID,
		Name:        "legacy-baseline-" + inputs.NodeID,
		Description: "Converted from the legacy Network Guard baseline (NFTInputs). Read-only until adopted.",
		Rules:       rules,
		CreatedAt:   inputs.CreatedAt,
		UpdatedAt:   inputs.UpdatedAt,
	}

	binding := model.NodeGuardBinding{
		NodeID:    inputs.NodeID,
		GroupIDs:  []string{groupID},
		Managed:   false,
		CreatedAt: inputs.CreatedAt,
		UpdatedAt: inputs.UpdatedAt,
	}

	zones := []model.GuardZone{
		{
			ID:         model.GuardZonePublic,
			Name:       "public",
			Builtin:    true,
			Interfaces: []string{iface},
		},
		{
			ID:      model.GuardZoneWireGuard,
			Name:    "wireguard",
			Builtin: true,
			CIDRs:   []string{wgCIDR},
		},
		{
			ID:         model.GuardZoneLoopback,
			Name:       "loopback",
			Builtin:    true,
			Interfaces: []string{"lo"},
		},
	}

	return LegacyView{Group: group, Binding: binding, Zones: zones}
}
