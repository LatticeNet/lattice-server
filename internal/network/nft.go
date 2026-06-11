package network

import (
	"fmt"
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

func GenerateNFTPlan(p NFTPlan) (string, error) {
	if p.InterfaceName == "" {
		p.InterfaceName = "eth0"
	}
	if p.WireGuardCIDR == "" {
		p.WireGuardCIDR = "10.66.0.0/24"
	}
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
	fmt.Fprintf(&b, "  set wg_peers4 {\n    type ipv4_addr\n    flags interval\n    elements = { %s }\n  }\n\n", p.WireGuardCIDR)
	fmt.Fprintf(&b, "  chain input {\n")
	fmt.Fprintf(&b, "    type filter hook input priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
	fmt.Fprintf(&b, "    iif lo accept\n")
	if len(p.PublicTCP) > 0 {
		fmt.Fprintf(&b, "    tcp dport { %s } accept comment \"public lattice ports\"\n", joinPorts(p.PublicTCP))
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
