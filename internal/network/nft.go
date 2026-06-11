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
	WireGuardTCP  []int  `json:"wireguard_tcp"`
	WireGuardUDP  []int  `json:"wireguard_udp"`
}

// ifaceNameRe matches Linux network interface names: up to 15 chars (IFNAMSIZ-1)
// drawn from a conservative set. This boundary stops attacker input from
// breaking out of the nft statement it is interpolated into.
var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

func GenerateNFTPlan(p NFTPlan) (string, error) {
	if p.InterfaceName == "" {
		p.InterfaceName = "eth0"
	}
	if !ifaceNameRe.MatchString(p.InterfaceName) {
		return "", fmt.Errorf("invalid interface name %q", p.InterfaceName)
	}
	if p.WireGuardCIDR == "" {
		p.WireGuardCIDR = "10.66.0.0/24"
	}
	// Parse and re-emit the CIDR in canonical form. This rejects malformed input
	// and guarantees the value interpolated into the ruleset is a plain network
	// address with no injected nftables syntax.
	_, ipNet, err := net.ParseCIDR(p.WireGuardCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid wireguard cidr %q: %w", p.WireGuardCIDR, err)
	}
	if ipNet.IP.To4() == nil {
		return "", fmt.Errorf("wireguard cidr %q must be IPv4", p.WireGuardCIDR)
	}
	canonicalCIDR := ipNet.String()
	if err := validatePorts(p.PublicTCP); err != nil {
		return "", fmt.Errorf("public tcp: %w", err)
	}
	if err := validatePorts(p.WireGuardTCP); err != nil {
		return "", fmt.Errorf("wireguard tcp: %w", err)
	}
	if err := validatePorts(p.WireGuardUDP); err != nil {
		return "", fmt.Errorf("wireguard udp: %w", err)
	}
	sort.Ints(p.PublicTCP)
	sort.Ints(p.WireGuardTCP)
	sort.Ints(p.WireGuardUDP)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet lattice_guard {\n")
	fmt.Fprintf(&b, "  set wg_peers4 {\n    type ipv4_addr\n    flags interval\n    elements = { %s }\n  }\n\n", canonicalCIDR)
	fmt.Fprintf(&b, "  chain input {\n")
	fmt.Fprintf(&b, "    type filter hook input priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
	fmt.Fprintf(&b, "    iif lo accept\n")
	if len(p.PublicTCP) > 0 {
		fmt.Fprintf(&b, "    iifname \"%s\" tcp dport { %s } accept comment \"public lattice ports\"\n", p.InterfaceName, joinPorts(p.PublicTCP))
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

func validatePorts(ports []int) error {
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %d", p)
		}
	}
	return nil
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	return strings.Join(parts, ", ")
}
