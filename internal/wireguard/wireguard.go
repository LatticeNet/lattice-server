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
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
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

func ValidatePublicKey(key string) bool {
	return wgKeyRe.MatchString(key)
}

func ValidateEndpoint(endpoint string) error {
	return validateEndpoint(endpoint)
}

// Interface is the [Interface] section for the target node.
type Interface struct {
	Name       string
	Address    string // mesh address, e.g. 10.66.0.1/24
	ListenPort int
	MTU        int      // rendered only when > 0
	DNS        []string // resolver IPs; rendered only when non-empty
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
		// Pin AllowedIPs to the peer's single host route. A node-reported
		// WireGuardIP is attacker-influenced metadata; if it carries a wide
		// prefix (e.g. "10.66.0.0/16") routing that whole range to one peer
		// would let it intercept/impersonate other nodes' mesh traffic. An
		// unparseable address means we cannot bound the peer safely, so skip it.
		allowed := hostCIDR(n.WireGuardIP)
		if allowed == "" {
			continue
		}
		peers = append(peers, Peer{
			Name:       n.Name,
			PublicKey:  n.WireGuardPublicKey,
			AllowedIPs: allowed,
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
	if iface.MTU != 0 && (iface.MTU < 576 || iface.MTU > 9000) {
		return "", fmt.Errorf("invalid mtu %d", iface.MTU)
	}
	for _, dns := range iface.DNS {
		if net.ParseIP(dns) == nil {
			return "", fmt.Errorf("invalid dns address %q", dns)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", iface.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", iface.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", PrivateKeyPlaceholder)
	if iface.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", iface.MTU)
	}
	if len(iface.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(iface.DNS, ", "))
	}
	for _, p := range peers {
		if !ValidatePublicKey(p.PublicKey) {
			return "", fmt.Errorf("invalid public key for peer %q", p.Name)
		}
		if err := validateAllowedIPs(p.AllowedIPs); err != nil {
			return "", fmt.Errorf("peer %q: %w", p.Name, err)
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

// validateAllowedIPs accepts one or more comma-separated CIDRs. A hub may
// advertise additive routes beyond its own pinned host route, so this is no
// longer a single-value field; every element must still parse as a CIDR so
// nothing operator-influenced reaches the config uncanonicalized.
func validateAllowedIPs(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("empty allowed ips")
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if _, _, err := net.ParseCIDR(part); err != nil {
			return fmt.Errorf("invalid allowed ips %q: %w", part, err)
		}
	}
	return nil
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
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid endpoint port in %q", ep)
	}
	return nil
}

func sanitizeComment(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}

// hostCIDR normalizes a node-reported mesh address into a single-host route:
// /32 for IPv4, /128 for IPv6. Any prefix on the input is discarded — only the
// host IP is kept — so a node cannot widen its own AllowedIPs (e.g. report
// "10.66.0.5/16" to get a /16 routed to it). The address may be a bare IP or a
// CIDR; an unparseable value returns "" so the caller skips that peer.
func hostCIDR(addr string) string {
	host := addr
	// Strip any prefix and keep only the host IP. ParseCIDR returns the masked
	// network in the *IPNet, so we use the first (IP) return value, which is the
	// original host address with the prefix removed.
	if strings.Contains(addr, "/") {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			return ""
		}
		host = ip.String()
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return ""
	}
	if parsed.To4() == nil {
		return parsed.String() + "/128"
	}
	return parsed.String() + "/32"
}

func ensureCIDR(ip string, bits int) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	return fmt.Sprintf("%s/%d", ip, bits)
}
