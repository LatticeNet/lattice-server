package wireguard

import (
	"errors"
	"fmt"
	"sort"

	"github.com/LatticeNet/lattice-sdk/model"
)

// BuildTopology generalizes BuildMesh to named networks with explicit
// topologies (design-13 §5.3). The security invariants of BuildMesh are
// preserved verbatim:
//
//   - a peer's own address is always pinned to a host route (/32 or /128), so
//     a member reporting a wide prefix can never intercept another member's
//     traffic;
//   - additive routes come only from a hub's reviewed ExtraAllowedIPs, never
//     from a member's self-reported address;
//   - the target's private key never enters this package.
//
// Mesh mode reproduces BuildMesh byte-for-byte for the same fleet, which is
// the migration gate for the existing implicit mesh.

// ErrCustomTopology marks the not-yet-implemented explicit-edge mode. It fails
// closed rather than silently degrading to mesh, which would quietly widen a
// deliberately restricted topology.
var ErrCustomTopology = errors.New("custom topology is not implemented; use mesh or hub-and-spoke")

// BuildTopology computes the interface and peers for one member of a network.
// nodes supplies the public keys and fallback endpoints; memberships define
// the topology roles and addresses.
func BuildTopology(
	network model.WGNetwork,
	memberships []model.WGMembership,
	nodes []model.Node,
	targetNodeID string,
) (Interface, []Peer, error) {
	target, ok := membershipFor(memberships, targetNodeID)
	if !ok {
		return Interface{}, nil, fmt.Errorf("node %q is not a member of network %q", targetNodeID, network.ID)
	}
	if target.Address == "" {
		return Interface{}, nil, fmt.Errorf("member %q has no address", targetNodeID)
	}

	byID := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	iface := Interface{
		Name:       firstNonEmpty(target.InterfaceName, "wg0"),
		Address:    ensureCIDR(target.Address, 24),
		ListenPort: firstNonZero(target.ListenPort, network.ListenPort, byID[targetNodeID].WireGuardPort, model.WGDefaultListenPort),
		MTU:        firstNonZero(target.MTU, network.MTU),
		DNS:        append([]string(nil), network.DNS...),
	}

	var peers []Peer
	for _, member := range memberships {
		if member.NodeID == targetNodeID {
			continue
		}
		node, ok := byID[member.NodeID]
		if !ok || node.WireGuardPublicKey == "" || member.Address == "" {
			continue
		}
		linked, err := peersWith(network.Topology, target, member)
		if err != nil {
			return Interface{}, nil, err
		}
		if !linked {
			continue
		}
		// The peer's own address is always a host route. Extra routes are only
		// honored from a hub, and only when the target is not itself that hub.
		allowed := hostCIDR(member.Address)
		if allowed == "" {
			continue
		}
		allowedIPs := []string{allowed}
		if member.Role == model.WGRoleHub {
			allowedIPs = append(allowedIPs, member.ExtraAllowedIPs...)
		}
		peers = append(peers, Peer{
			Name:       node.Name,
			PublicKey:  node.WireGuardPublicKey,
			AllowedIPs: joinAllowedIPs(allowedIPs),
			Endpoint:   firstNonEmpty(member.Endpoint, node.WireGuardEndpoint),
			Keepalive:  firstNonZero(member.Keepalive, network.Keepalive, model.WGDefaultKeepalive),
		})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].AllowedIPs < peers[j].AllowedIPs })
	return iface, peers, nil
}

// peersWith reports whether target should carry a [Peer] section for member.
func peersWith(topology string, target, member model.WGMembership) (bool, error) {
	switch topology {
	case model.WGTopologyMesh, "":
		return true, nil
	case model.WGTopologyHubSpoke:
		// Spokes peer only with hubs; hubs peer with everyone.
		if target.Role == model.WGRoleHub || member.Role == model.WGRoleHub {
			return true, nil
		}
		return false, nil
	case model.WGTopologyCustom:
		return false, ErrCustomTopology
	default:
		return false, fmt.Errorf("invalid topology %q", topology)
	}
}

// MeshFromNodes converts the existing implicit fleet mesh — the one encoded in
// Node.WireGuard* fields — into a named network plus memberships. It is the
// migration bridge: BuildTopology over its output must render identically to
// BuildMesh over the same nodes.
func MeshFromNodes(nodes []model.Node, listenPort int) (model.WGNetwork, []model.WGMembership) {
	network := model.WGNetwork{
		ID:         "default",
		Name:       "default",
		Topology:   model.WGTopologyMesh,
		ListenPort: listenPort,
		Keepalive:  defaultKeepalive,
	}
	members := make([]model.WGMembership, 0, len(nodes))
	for _, n := range nodes {
		if n.WireGuardIP == "" {
			continue
		}
		members = append(members, model.WGMembership{
			NetworkID:  network.ID,
			NodeID:     n.ID,
			Address:    n.WireGuardIP,
			Role:       model.WGRolePeer,
			ListenPort: n.WireGuardPort,
			Endpoint:   n.WireGuardEndpoint,
		})
	}
	return network, members
}

func membershipFor(memberships []model.WGMembership, nodeID string) (model.WGMembership, bool) {
	for _, m := range memberships {
		if m.NodeID == nodeID {
			return m, true
		}
	}
	return model.WGMembership{}, false
}

func joinAllowedIPs(values []string) string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	result := ""
	for i, v := range out {
		if i > 0 {
			result += ", "
		}
		result += v
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}
