package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type NFTPlan struct {
	InterfaceName string `json:"interface_name"`
	WireGuardCIDR string `json:"wireguard_cidr"`
	PublicTCP     []int  `json:"public_tcp"`
	PublicUDP     []int  `json:"public_udp"`
	WireGuardTCP  []int  `json:"wireguard_tcp"`
	WireGuardUDP  []int  `json:"wireguard_udp"`

	// InputRules are server-composed policy rules folded into the single
	// lattice_guard input chain. They are intentionally not part of the public
	// JSON API for raw Network Guard inputs; callers must pass structured,
	// validated intent through server-owned compilers.
	InputRules []NFTInputRule `json:"-"`
}

const (
	NFTActionAccept = "accept"
	NFTActionDrop   = "drop"

	NFTProtoTCP = "tcp"
	NFTProtoUDP = "udp"
	NFTProtoAny = "any"
)

type NFTInputRule struct {
	// Interface, when set, scopes the rule to traffic arriving on that inbound
	// interface (rendered as `iifname "<name>"`). It is how a trusted overlay
	// zone (wireguard, tailscale) is accepted without widening the public
	// surface. Empty means "any inbound interface".
	Interface   string
	SourceCIDRs []string
	Protocol    string
	Ports       []int
	Action      string
	Comment     string
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
	fmt.Fprintf(&b, "destroy table inet lattice_guard\n")
	fmt.Fprintf(&b, "table inet lattice_guard {\n")
	fmt.Fprintf(&b, "  set wg_peers4 {\n    type ipv4_addr\n    flags interval\n    elements = { %s }\n  }\n\n", p.WireGuardCIDR)
	fmt.Fprintf(&b, "  chain input {\n")
	fmt.Fprintf(&b, "    type filter hook input priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
	fmt.Fprintf(&b, "    iif lo accept\n")
	for _, rule := range p.InputRules {
		for _, line := range renderInputRule(rule) {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
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
	if p.InputRules, err = normalizeInputRules(p.InputRules); err != nil {
		return NFTPlan{}, err
	}
	return p, nil
}

func normalizeInputRules(rules []NFTInputRule) ([]NFTInputRule, error) {
	out := make([]NFTInputRule, 0, len(rules))
	for i, rule := range rules {
		normalized, err := normalizeInputRule(rule)
		if err != nil {
			return nil, fmt.Errorf("input rule %d: %w", i+1, err)
		}
		out = append(out, normalized)
	}
	return out, nil
}

func normalizeInputRule(rule NFTInputRule) (NFTInputRule, error) {
	switch rule.Action {
	case NFTActionAccept, NFTActionDrop:
	default:
		return NFTInputRule{}, fmt.Errorf("invalid action %q", rule.Action)
	}
	switch rule.Protocol {
	case NFTProtoTCP, NFTProtoUDP, NFTProtoAny:
	default:
		return NFTInputRule{}, fmt.Errorf("invalid protocol %q", rule.Protocol)
	}
	if rule.Interface != "" && !ifaceNameRe.MatchString(rule.Interface) {
		return NFTInputRule{}, fmt.Errorf("invalid interface name %q", rule.Interface)
	}
	var err error
	if rule.Ports, err = normalizePorts(rule.Ports); err != nil {
		return NFTInputRule{}, fmt.Errorf("ports: %w", err)
	}
	if rule.Protocol == NFTProtoAny && len(rule.Ports) > 0 {
		return NFTInputRule{}, errors.New("protocol any cannot carry ports")
	}
	rule.SourceCIDRs, err = normalizeSourceCIDRs(rule.SourceCIDRs)
	if err != nil {
		return NFTInputRule{}, err
	}
	rule.Comment = strings.TrimSpace(rule.Comment)
	return rule, nil
}

func normalizeSourceCIDRs(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		normalized, err := normalizeSourceCIDR(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		return sourceCIDRSortKey(out[i]) < sourceCIDRSortKey(out[j])
	})
	return out, nil
}

func normalizeSourceCIDR(value string) (string, error) {
	if ip := net.ParseIP(value); ip != nil {
		v4 := ip.To4()
		if v4 != nil {
			return v4.String(), nil
		}
		if ip.To16() != nil {
			return ip.String(), nil
		}
	}
	ip, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		return "", fmt.Errorf("invalid source %q", value)
	}
	if ip.To4() != nil && ipNet.IP.To4() != nil {
		if ones, bits := ipNet.Mask.Size(); bits == 32 && ones == 32 {
			return ipNet.IP.To4().String(), nil
		}
		return ipNet.String(), nil
	}
	if ip.To16() != nil && ip.To4() == nil && ipNet.IP.To16() != nil {
		if ones, bits := ipNet.Mask.Size(); bits == 128 && ones == 128 {
			return ipNet.IP.String(), nil
		}
		return ipNet.String(), nil
	}
	return "", fmt.Errorf("invalid source %q", value)
}

func sourceCIDRSortKey(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		family := "4:"
		if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			family = "6:"
		}
		return family + prefix.String()
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		family := "4:"
		if addr.Is6() && !addr.Is4In6() {
			family = "6:"
		}
		return family + addr.String()
	}
	return value
}

func renderInputRule(rule NFTInputRule) []string {
	sourceExprs := inputSourceExprs(rule.SourceCIDRs)
	if len(sourceExprs) == 0 {
		sourceExprs = []string{""}
	}
	lines := make([]string, 0, len(sourceExprs))
	for _, sourceExpr := range sourceExprs {
		parts := []string{}
		if rule.Interface != "" {
			parts = append(parts, fmt.Sprintf("iifname %q", rule.Interface))
		}
		if sourceExpr != "" {
			parts = append(parts, sourceExpr)
		}
		if rule.Protocol != NFTProtoAny {
			if len(rule.Ports) == 0 {
				parts = append(parts, "meta l4proto "+rule.Protocol)
			} else {
				parts = append(parts, rule.Protocol+" dport { "+joinPorts(rule.Ports)+" }")
			}
		}
		parts = append(parts, rule.Action)
		if rule.Comment != "" {
			parts = append(parts, "comment", strconv.Quote(rule.Comment))
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines
}

func inputSourceExprs(values []string) []string {
	var v4, v6 []string
	for _, value := range values {
		if addr, ok := sourceAddr(value); ok {
			if addr.Is4() {
				v4 = append(v4, value)
			} else if addr.Is6() && !addr.Is4In6() {
				v6 = append(v6, value)
			}
		}
	}
	out := make([]string, 0, 2)
	if len(v4) > 0 {
		out = append(out, sourceExpr("ip", v4))
	}
	if len(v6) > 0 {
		out = append(out, sourceExpr("ip6", v6))
	}
	return out
}

func sourceAddr(value string) (netip.Addr, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr, true
	}
	return netip.Addr{}, false
}

func sourceExpr(family string, values []string) string {
	if len(values) == 1 {
		return family + " saddr " + values[0]
	}
	return family + " saddr { " + strings.Join(values, ", ") + " }"
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
