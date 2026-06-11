// Package wireguard generates per-node WireGuard configuration for a cluster
// mesh. The server is the topology brain: given each node's public key, mesh IP,
// and (optional) public endpoint, it emits a wg0.conf for a target node with one
// [Peer] per other node, AllowedIPs pinned to each peer's /32 (so a node can
// only impersonate its own mesh IP), and a keepalive so NAT-bound nodes hold the
// tunnel open. The node's private key never reaches the server; the emitted
// config carries the PrivateKeyPlaceholder token, which the agent substitutes
// from its local key file at apply time.
package wireguard

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// PrivateKeyPlaceholder is replaced by the agent with the node's local private
// key when the config is applied. It is safe to display in an approval diff.
const PrivateKeyPlaceholder = "__LATTICE_WG_PRIVATE_KEY__"

const defaultKeepalive = 25

// wgKeyRe loosely validates a base64 WireGuard key (44 chars ending in '=').
var wgKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{42,43}=$`)

// ifaceNameRe bounds the interface name to a safe charset.
var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// Interface is the [Interface] section for the target node.
type Interface struct {
	Name       string
	Address    string // mesh address, e.g. 10.66.0.1/24
	ListenPort int
}

// Peer is one [Peer] section.
type Peer struct {
	Name       string // comment only
	PublicKey  string
	AllowedIPs string // typically <mesh-ip>/32
	Endpoint   string // host:port, empty for dial-out-only nodes
	Keepalive  int
}

// BuildMesh computes the interface and peer list for target from the cluster's
// nodes. Nodes without a public key or mesh IP, and the target itself, are
// skipped. listenPort overrides the target's reported port when > 0.
func BuildMesh(nodes []model.Node, target model.Node, listenPort int) (Interface, []Peer, error) {
	if target.WireGuardIP == "" {
		return Interface{}, nil, fmt.Errorf("target node %q has no wireguard_ip", target.ID)
	}
	port := listenPort
	if port == 0 {
		port = target.WireGuardPort
	}
	if port == 0 {
		port = 51820
	}
	iface := Interface{
		Name:       "wg0",
		Address:    ensureCIDR(target.WireGuardIP, 24),
		ListenPort: port,
	}
	var peers []Peer
	for _, n := range nodes {
		if n.ID == target.ID || n.WireGuardPublicKey == "" || n.WireGuardIP == "" {
			continue
		}
		peers = append(peers, Peer{
			Name:       n.Name,
			PublicKey:  n.WireGuardPublicKey,
			AllowedIPs: hostCIDR(n.WireGuardIP),
			Endpoint:   n.WireGuardEndpoint,
			Keepalive:  defaultKeepalive,
		})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].AllowedIPs < peers[j].AllowedIPs })
	return iface, peers, nil
}

// GenerateConfig renders a wg0.conf. It validates keys and the interface name so
// attacker-influenced metadata cannot break out of the config structure.
func GenerateConfig(iface Interface, peers []Peer) (string, error) {
	if iface.Name == "" {
		iface.Name = "wg0"
	}
	if !ifaceNameRe.MatchString(iface.Name) {
		return "", fmt.Errorf("invalid interface name %q", iface.Name)
	}
	if iface.ListenPort < 1 || iface.ListenPort > 65535 {
		return "", fmt.Errorf("invalid listen port %d", iface.ListenPort)
	}
	if _, _, err := net.ParseCIDR(iface.Address); err != nil {
		return "", fmt.Errorf("invalid interface address %q: %w", iface.Address, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", iface.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", iface.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", PrivateKeyPlaceholder)
	for _, p := range peers {
		if !wgKeyRe.MatchString(p.PublicKey) {
			return "", fmt.Errorf("invalid public key for peer %q", p.Name)
		}
		if _, _, err := net.ParseCIDR(p.AllowedIPs); err != nil {
			return "", fmt.Errorf("invalid allowed ips %q: %w", p.AllowedIPs, err)
		}
		if err := validateEndpoint(p.Endpoint); err != nil {
			return "", fmt.Errorf("peer %q: %w", p.Name, err)
		}
		fmt.Fprintf(&b, "\n[Peer]\n")
		if p.Name != "" {
			fmt.Fprintf(&b, "# %s\n", sanitizeComment(p.Name))
		}
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", p.AllowedIPs)
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.String(), nil
}

func validateEndpoint(ep string) error {
	if ep == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: %w", ep, err)
	}
	if host == "" {
		return fmt.Errorf("invalid endpoint host in %q", ep)
	}
	if strings.ContainsAny(host, " \t\n") {
		return fmt.Errorf("invalid endpoint host in %q", ep)
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return fmt.Errorf("invalid endpoint port in %q", ep)
		}
	}
	return nil
}

func sanitizeComment(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}

// hostCIDR turns a bare mesh IP into a /32 (or /128) host route.
func hostCIDR(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return ip + "/128"
	}
	return ip + "/32"
}

func ensureCIDR(ip string, bits int) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	return fmt.Sprintf("%s/%d", ip, bits)
}
