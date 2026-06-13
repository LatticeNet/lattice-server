package network

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

type NFTPlan struct {
	InterfaceName string `json:"interface_name"`
	WireGuardCIDR string `json:"wireguard_cidr"`
	PublicTCP     []int  `json:"public_tcp"`
	PublicUDP     []int  `json:"public_udp"`
	WireGuardTCP  []int  `json:"wireguard_tcp"`
	WireGuardUDP  []int  `json:"wireguard_udp"`
}

// ifaceNameRe matches Linux network interface names: up to 15 chars (IFNAMSIZ-1)
// drawn from a conservative set. This boundary stops attacker input from
// breaking out of the nft statement it is interpolated into.
var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

func GenerateNFTPlan(p NFTPlan) (string, error) {
	p, err := NormalizeNFTPlan(p)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet lattice_guard {\n")
	fmt.Fprintf(&b, "  set wg_peers4 {\n    type ipv4_addr\n    flags interval\n    elements = { %s }\n  }\n\n", p.WireGuardCIDR)
	fmt.Fprintf(&b, "  chain input {\n")
	fmt.Fprintf(&b, "    type filter hook input priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
	fmt.Fprintf(&b, "    iif lo accept\n")
	if len(p.PublicTCP) > 0 {
		fmt.Fprintf(&b, "    iifname \"%s\" tcp dport { %s } accept comment \"public lattice tcp ports\"\n", p.InterfaceName, joinPorts(p.PublicTCP))
	}
	if len(p.PublicUDP) > 0 {
		fmt.Fprintf(&b, "    iifname \"%s\" udp dport { %s } accept comment \"public lattice udp ports\"\n", p.InterfaceName, joinPorts(p.PublicUDP))
	}
	if len(p.WireGuardTCP) > 0 {
		fmt.Fprintf(&b, "    ip saddr @wg_peers4 tcp dport { %s } accept comment \"wg tcp services\"\n", joinPorts(p.WireGuardTCP))
	}
	if len(p.WireGuardUDP) > 0 {
		fmt.Fprintf(&b, "    ip saddr @wg_peers4 udp dport { %s } accept comment \"wg udp services\"\n", joinPorts(p.WireGuardUDP))
	}
	fmt.Fprintf(&b, "    counter drop\n")
	fmt.Fprintf(&b, "  }\n}\n")
	return b.String(), nil
}

// NormalizeNFTPlan applies defaults, validates every operator-controlled value,
// canonicalizes the WG CIDR, and returns sorted/deduplicated port lists.
func NormalizeNFTPlan(p NFTPlan) (NFTPlan, error) {
	if p.InterfaceName == "" {
		p.InterfaceName = "eth0"
	}
	if !ifaceNameRe.MatchString(p.InterfaceName) {
		return NFTPlan{}, fmt.Errorf("invalid interface name %q", p.InterfaceName)
	}
	if p.WireGuardCIDR == "" {
		p.WireGuardCIDR = "10.66.0.0/24"
	}
	// Parse and re-emit the CIDR in canonical form. This rejects malformed input
	// and guarantees the value interpolated into the ruleset is a plain network
	// address with no injected nftables syntax.
	_, ipNet, err := net.ParseCIDR(p.WireGuardCIDR)
	if err != nil {
		return NFTPlan{}, fmt.Errorf("invalid wireguard cidr %q: %w", p.WireGuardCIDR, err)
	}
	if ipNet.IP.To4() == nil {
		return NFTPlan{}, fmt.Errorf("wireguard cidr %q must be IPv4", p.WireGuardCIDR)
	}
	p.WireGuardCIDR = ipNet.String()
	if p.PublicTCP, err = normalizePorts(p.PublicTCP); err != nil {
		return NFTPlan{}, fmt.Errorf("public tcp: %w", err)
	}
	if p.PublicUDP, err = normalizePorts(p.PublicUDP); err != nil {
		return NFTPlan{}, fmt.Errorf("public udp: %w", err)
	}
	if p.WireGuardTCP, err = normalizePorts(p.WireGuardTCP); err != nil {
		return NFTPlan{}, fmt.Errorf("wireguard tcp: %w", err)
	}
	if p.WireGuardUDP, err = normalizePorts(p.WireGuardUDP); err != nil {
		return NFTPlan{}, fmt.Errorf("wireguard udp: %w", err)
	}
	return p, nil
}

func normalizePorts(ports []int) ([]int, error) {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %d", p)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	return strings.Join(parts, ", ")
}
