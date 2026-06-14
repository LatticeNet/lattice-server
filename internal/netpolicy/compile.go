package netpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

type CompileOptions struct {
	ControlPlaneIPv4 netip.Addr
	ControlPlanePort int
}

// CompileEgressRuleset renders a per-node egress policy into a deterministic
// nftables batch. It intentionally owns a separate lattice_policy table so this
// first committed path cannot conflict with the existing lattice_guard input
// table used by baseline node firewall inputs.
func CompileEgressRuleset(policy model.NetPolicy, resolve NodeResolver, opts CompileOptions) (string, error) {
	if resolve == nil {
		return "", errors.New("node resolver is required")
	}
	if !policy.Enabled {
		return "", errors.New("netpolicy is disabled")
	}
	if !opts.ControlPlaneIPv4.IsValid() || !opts.ControlPlaneIPv4.Is4() {
		return "", errors.New("control-plane IPv4 is required")
	}
	if opts.ControlPlanePort < 1 || opts.ControlPlanePort > 65535 {
		return "", fmt.Errorf("invalid control-plane port %d", opts.ControlPlanePort)
	}
	normalized, err := NormalizePolicy(policy, resolve)
	if err != nil {
		return "", err
	}
	target, ok := resolve(normalized.TargetNodeID)
	if !ok {
		return "", fmt.Errorf("target node %q not found", normalized.TargetNodeID)
	}

	var b strings.Builder
	b.WriteString("destroy table inet lattice_policy\n")
	b.WriteString("table inet lattice_policy {\n")
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority 0; policy drop;\n")
	b.WriteString("\t\tct state established,related accept comment \"lattice established\"\n")
	b.WriteString("\t\toifname \"lo\" accept comment \"lattice loopback\"\n")
	fmt.Fprintf(&b, "\t\tip daddr %s tcp dport %d accept comment \"lattice control-plane\"\n", opts.ControlPlaneIPv4.String(), opts.ControlPlanePort)
	b.WriteString("\t\tudp dport 53 accept comment \"lattice dns udp\"\n")
	b.WriteString("\t\ttcp dport 53 accept comment \"lattice dns tcp\"\n")

	for _, rule := range normalized.Rules {
		if rule.Direction != model.NetDirEgress {
			return "", fmt.Errorf("rule %s uses unsupported direction %q; egress-only MVP", rule.ID, rule.Direction)
		}
		if rule.Disabled {
			continue
		}
		line, err := compileEgressRule(rule, target, resolve)
		if err != nil {
			return "", err
		}
		b.WriteString("\t\t")
		b.WriteString(line)
		b.WriteByte('\n')
	}

	b.WriteString("\t\tcounter drop comment \"lattice default drop\"\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func compileEgressRule(rule model.NetRule, target model.Node, resolve NodeResolver) (string, error) {
	parts := []string{}
	remoteExpr, err := egressRemoteExpr(rule, target, resolve)
	if err != nil {
		return "", err
	}
	if remoteExpr != "" {
		parts = append(parts, remoteExpr)
	}
	protoExpr, err := egressProtoExpr(rule)
	if err != nil {
		return "", err
	}
	if protoExpr != "" {
		parts = append(parts, protoExpr)
	}
	action := "drop"
	if rule.Action == model.NetRuleAllow {
		action = "accept"
	}
	parts = append(parts, action, "comment", strconv.Quote(ruleComment(rule)))
	return strings.Join(parts, " "), nil
}

func egressRemoteExpr(rule model.NetRule, target model.Node, resolve NodeResolver) (string, error) {
	switch rule.Remote.Kind {
	case model.NetRefAny:
		return "", nil
	case model.NetRefCIDR:
		return "ip daddr " + rule.Remote.CIDR, nil
	case model.NetRefNode:
		if rule.Remote.NodeID == target.ID {
			return "", fmt.Errorf("rule %s remote node cannot be the target node", rule.ID)
		}
		remote, ok := resolve(rule.Remote.NodeID)
		if !ok {
			return "", fmt.Errorf("rule %s remote node %q not found", rule.ID, rule.Remote.NodeID)
		}
		addrs := nodeIPv4s(remote)
		if len(addrs) == 0 {
			return "", fmt.Errorf("rule %s remote node %q has no IPv4 address to compile", rule.ID, rule.Remote.NodeID)
		}
		if len(addrs) == 1 {
			return "ip daddr " + addrs[0], nil
		}
		return "ip daddr { " + strings.Join(addrs, ", ") + " }", nil
	default:
		return "", fmt.Errorf("rule %s has invalid remote kind %q", rule.ID, rule.Remote.Kind)
	}
}

func egressProtoExpr(rule model.NetRule) (string, error) {
	switch rule.Protocol {
	case model.NetProtoAny:
		if len(rule.Ports) > 0 {
			return "", fmt.Errorf("rule %s protocol any cannot carry ports", rule.ID)
		}
		return "", nil
	case model.NetProtoTCP, model.NetProtoUDP:
		if len(rule.Ports) == 0 {
			return "meta l4proto " + rule.Protocol, nil
		}
		return rule.Protocol + " dport " + nftPortSet(rule.Ports), nil
	default:
		return "", fmt.Errorf("rule %s has invalid protocol %q", rule.ID, rule.Protocol)
	}
}

func nftPortSet(ports []int) string {
	if len(ports) == 1 {
		return strconv.Itoa(ports[0])
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, strconv.Itoa(p))
	}
	return "{ " + strings.Join(out, ", ") + " }"
}

func nodeIPv4s(node model.Node) []string {
	seen := map[string]struct{}{}
	for _, raw := range []string{node.WireGuardIP, node.PublicIP} {
		if addr, ok := parseNodeIPv4(raw); ok {
			seen[addr.String()] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for addr := range seen {
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool {
		return netip.MustParseAddr(out[i]).Compare(netip.MustParseAddr(out[j])) < 0
	})
	return out
}

func parseNodeIPv4(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, false
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		addr := prefix.Addr()
		return addr, addr.Is4()
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}

func ruleComment(rule model.NetRule) string {
	base := "lattice rule " + rule.ID
	if rule.Comment == "" {
		return base
	}
	return base + " " + rule.Comment
}
