package netpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

type CompileOptions struct {
	ControlPlaneIPv4 netip.Addr
	ControlPlaneIPv6 netip.Addr
	ControlPlaneHost string
	ControlPlanePort int
}

type DomainSet struct {
	Host string `json:"host"`
	Set4 string `json:"set4"`
	Set6 string `json:"set6"`
}

type EgressPlan struct {
	Ruleset    string      `json:"ruleset"`
	DomainSets []DomainSet `json:"domain_sets,omitempty"`
}

// CompileEgressRuleset renders a per-node egress policy into a deterministic
// nftables batch. It intentionally owns a separate lattice_policy table so this
// first committed path cannot conflict with the existing lattice_guard input
// table used by baseline node firewall inputs.
func CompileEgressRuleset(policy model.NetPolicy, resolve NodeResolver, opts CompileOptions) (string, error) {
	plan, err := CompileEgressPlan(policy, resolve, opts)
	if err != nil {
		return "", err
	}
	return plan.Ruleset, nil
}

// CompileEgressPlan returns the nftables batch plus the domain-backed named sets
// that must be populated on the node before the selfcheck runs.
func CompileEgressPlan(policy model.NetPolicy, resolve NodeResolver, opts CompileOptions) (EgressPlan, error) {
	if resolve == nil {
		return EgressPlan{}, errors.New("node resolver is required")
	}
	if !policy.Enabled {
		return EgressPlan{}, errors.New("netpolicy is disabled")
	}
	if err := validateCompileOptions(opts); err != nil {
		return EgressPlan{}, err
	}
	normalized, err := NormalizePolicy(policy, resolve)
	if err != nil {
		return EgressPlan{}, err
	}
	target, ok := resolve(normalized.TargetNodeID)
	if !ok {
		return EgressPlan{}, fmt.Errorf("target node %q not found", normalized.TargetNodeID)
	}
	domainSets := collectEgressDomainSets(normalized.Rules)
	domainSetByHost := make(map[string]DomainSet, len(domainSets))
	for _, set := range domainSets {
		domainSetByHost[set.Host] = set
	}

	var b strings.Builder
	b.WriteString("destroy table inet lattice_policy\n")
	b.WriteString("table inet lattice_policy {\n")
	if opts.ControlPlaneHost != "" {
		b.WriteString("\tset lattice_control4 {\n")
		b.WriteString("\t\ttype ipv4_addr\n")
		b.WriteString("\t\tflags interval\n")
		b.WriteString("\t}\n\n")
		b.WriteString("\tset lattice_control6 {\n")
		b.WriteString("\t\ttype ipv6_addr\n")
		b.WriteString("\t\tflags interval\n")
		b.WriteString("\t}\n\n")
	}
	for _, set := range domainSets {
		b.WriteString("\tset ")
		b.WriteString(set.Set4)
		b.WriteString(" {\n")
		b.WriteString("\t\ttype ipv4_addr\n")
		b.WriteString("\t\tflags interval\n")
		b.WriteString("\t}\n\n")
		b.WriteString("\tset ")
		b.WriteString(set.Set6)
		b.WriteString(" {\n")
		b.WriteString("\t\ttype ipv6_addr\n")
		b.WriteString("\t\tflags interval\n")
		b.WriteString("\t}\n\n")
	}
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority 0; policy drop;\n")
	b.WriteString("\t\tct state established,related accept comment \"lattice established\"\n")
	b.WriteString("\t\toifname \"lo\" accept comment \"lattice loopback\"\n")
	b.WriteString(controlPlaneAllowLine(opts))
	b.WriteString("\t\tudp dport 53 accept comment \"lattice dns udp\"\n")
	b.WriteString("\t\ttcp dport 53 accept comment \"lattice dns tcp\"\n")

	for _, rule := range normalized.Rules {
		if rule.Direction != model.NetDirEgress {
			return EgressPlan{}, fmt.Errorf("rule %s uses unsupported direction %q; egress-only MVP", rule.ID, rule.Direction)
		}
		if rule.Disabled {
			continue
		}
		lines, err := compileEgressRule(rule, target, resolve, domainSetByHost)
		if err != nil {
			return EgressPlan{}, err
		}
		for _, line := range lines {
			b.WriteString("\t\t")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	b.WriteString("\t\tcounter drop comment \"lattice default drop\"\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return EgressPlan{Ruleset: b.String(), DomainSets: domainSets}, nil
}

func collectEgressDomainSets(rules []model.NetRule) []DomainSet {
	seen := map[string]DomainSet{}
	for _, rule := range rules {
		if rule.Disabled || rule.Direction != model.NetDirEgress || rule.Remote.Kind != model.NetRefDomain {
			continue
		}
		if _, ok := seen[rule.Remote.Domain]; !ok {
			seen[rule.Remote.Domain] = domainSetForHost(rule.Remote.Domain)
		}
	}
	out := make([]DomainSet, 0, len(seen))
	for _, set := range seen {
		out = append(out, set)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func domainSetForHost(host string) DomainSet {
	sum := sha256.Sum256([]byte("lattice-netpolicy-domain\x00" + host))
	suffix := hex.EncodeToString(sum[:])[:16]
	base := "lattice_dom_" + suffix
	return DomainSet{Host: host, Set4: base + "4", Set6: base + "6"}
}

func validateCompileOptions(opts CompileOptions) error {
	if opts.ControlPlanePort < 1 || opts.ControlPlanePort > 65535 {
		return fmt.Errorf("invalid control-plane port %d", opts.ControlPlanePort)
	}
	hasIPv4 := opts.ControlPlaneIPv4.IsValid()
	hasIPv6 := opts.ControlPlaneIPv6.IsValid()
	hasHost := strings.TrimSpace(opts.ControlPlaneHost) != ""
	if countTrue(hasIPv4, hasIPv6, hasHost) != 1 {
		return errors.New("exactly one control-plane IPv4, IPv6, or host is required")
	}
	switch {
	case hasIPv4:
		if !opts.ControlPlaneIPv4.Is4() {
			return errors.New("control-plane IPv4 must be IPv4")
		}
	case hasIPv6:
		if !opts.ControlPlaneIPv6.Is6() || opts.ControlPlaneIPv6.Is4In6() {
			return errors.New("control-plane IPv6 must be IPv6")
		}
	case hasHost:
		if strings.TrimSpace(opts.ControlPlaneHost) != opts.ControlPlaneHost {
			return errors.New("control-plane host must be normalized")
		}
	}
	return nil
}

func controlPlaneAllowLine(opts CompileOptions) string {
	if opts.ControlPlaneHost != "" {
		return fmt.Sprintf("\t\tip daddr @lattice_control4 tcp dport %d accept comment \"lattice control-plane domain\"\n", opts.ControlPlanePort) +
			fmt.Sprintf("\t\tip6 daddr @lattice_control6 tcp dport %d accept comment \"lattice control-plane domain6\"\n", opts.ControlPlanePort)
	}
	if opts.ControlPlaneIPv6.IsValid() {
		return fmt.Sprintf("\t\tip6 daddr %s tcp dport %d accept comment \"lattice control-plane\"\n", opts.ControlPlaneIPv6.String(), opts.ControlPlanePort)
	}
	return fmt.Sprintf("\t\tip daddr %s tcp dport %d accept comment \"lattice control-plane\"\n", opts.ControlPlaneIPv4.String(), opts.ControlPlanePort)
}

func countTrue(values ...bool) int {
	n := 0
	for _, value := range values {
		if value {
			n++
		}
	}
	return n
}

// CompileIngressInputRules extracts the ingress side of a per-node NetPolicy
// into typed lattice_guard input rules. It intentionally does not render nft
// syntax directly: the Network Guard renderer owns the single input chain so
// DNS/proxy/ACL providers cannot create competing default-drop hooks.
func CompileIngressInputRules(policy model.NetPolicy, resolve NodeResolver) ([]network.NFTInputRule, error) {
	if resolve == nil {
		return nil, errors.New("node resolver is required")
	}
	if !policy.Enabled {
		return nil, nil
	}
	normalized, err := NormalizePolicy(policy, resolve)
	if err != nil {
		return nil, err
	}
	target, ok := resolve(normalized.TargetNodeID)
	if !ok {
		return nil, fmt.Errorf("target node %q not found", normalized.TargetNodeID)
	}
	out := make([]network.NFTInputRule, 0, len(normalized.Rules))
	for _, rule := range normalized.Rules {
		if rule.Direction != model.NetDirIngress || rule.Disabled {
			continue
		}
		sources, err := ingressSourceCIDRs(rule, target, resolve)
		if err != nil {
			return nil, err
		}
		out = append(out, network.NFTInputRule{
			SourceCIDRs: sources,
			Protocol:    nftInputProtocol(rule.Protocol),
			Ports:       append([]int(nil), rule.Ports...),
			Action:      nftInputAction(rule.Action),
			Comment:     ruleComment(rule),
		})
	}
	return out, nil
}

func ingressSourceCIDRs(rule model.NetRule, target model.Node, resolve NodeResolver) ([]string, error) {
	switch rule.Remote.Kind {
	case model.NetRefAny:
		return nil, nil
	case model.NetRefCIDR:
		return []string{rule.Remote.CIDR}, nil
	case model.NetRefNode:
		if rule.Remote.NodeID == target.ID {
			return nil, fmt.Errorf("rule %s remote node cannot be the target node", rule.ID)
		}
		remote, ok := resolve(rule.Remote.NodeID)
		if !ok {
			return nil, fmt.Errorf("rule %s remote node %q not found", rule.ID, rule.Remote.NodeID)
		}
		v4, v6 := nodeIPAddrs(remote)
		if len(v4)+len(v6) == 0 {
			return nil, fmt.Errorf("rule %s remote node %q has no IP address to compile", rule.ID, rule.Remote.NodeID)
		}
		addrs := append(v4, v6...)
		return addrs, nil
	default:
		return nil, fmt.Errorf("rule %s has invalid remote kind %q", rule.ID, rule.Remote.Kind)
	}
}

func nftInputProtocol(proto string) string {
	switch proto {
	case model.NetProtoTCP:
		return network.NFTProtoTCP
	case model.NetProtoUDP:
		return network.NFTProtoUDP
	default:
		return network.NFTProtoAny
	}
}

func nftInputAction(action string) string {
	if action == model.NetRuleAllow {
		return network.NFTActionAccept
	}
	return network.NFTActionDrop
}

func compileEgressRule(rule model.NetRule, target model.Node, resolve NodeResolver, domainSets map[string]DomainSet) ([]string, error) {
	remoteExprs, err := egressRemoteExprs(rule, target, resolve, domainSets)
	if err != nil {
		return nil, err
	}
	protoExpr, err := egressProtoExpr(rule)
	if err != nil {
		return nil, err
	}
	action := "drop"
	if rule.Action == model.NetRuleAllow {
		action = "accept"
	}
	if len(remoteExprs) == 0 {
		remoteExprs = []string{""}
	}
	lines := make([]string, 0, len(remoteExprs))
	for _, remoteExpr := range remoteExprs {
		parts := []string{}
		if remoteExpr != "" {
			parts = append(parts, remoteExpr)
		}
		if protoExpr != "" {
			parts = append(parts, protoExpr)
		}
		parts = append(parts, action, "comment", strconv.Quote(ruleComment(rule)))
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines, nil
}

func egressRemoteExprs(rule model.NetRule, target model.Node, resolve NodeResolver, domainSets map[string]DomainSet) ([]string, error) {
	switch rule.Remote.Kind {
	case model.NetRefAny:
		return nil, nil
	case model.NetRefCIDR:
		return []string{nftAddrExpr("daddr", []string{rule.Remote.CIDR})}, nil
	case model.NetRefDomain:
		set, ok := domainSets[rule.Remote.Domain]
		if !ok {
			return nil, fmt.Errorf("rule %s domain %q has no compiled nft set", rule.ID, rule.Remote.Domain)
		}
		return []string{"ip daddr @" + set.Set4, "ip6 daddr @" + set.Set6}, nil
	case model.NetRefNode:
		if rule.Remote.NodeID == target.ID {
			return nil, fmt.Errorf("rule %s remote node cannot be the target node", rule.ID)
		}
		remote, ok := resolve(rule.Remote.NodeID)
		if !ok {
			return nil, fmt.Errorf("rule %s remote node %q not found", rule.ID, rule.Remote.NodeID)
		}
		v4, v6 := nodeIPAddrs(remote)
		if len(v4)+len(v6) == 0 {
			return nil, fmt.Errorf("rule %s remote node %q has no IP address to compile", rule.ID, rule.Remote.NodeID)
		}
		exprs := make([]string, 0, 2)
		if len(v4) > 0 {
			exprs = append(exprs, nftAddrExpr("daddr", v4))
		}
		if len(v6) > 0 {
			exprs = append(exprs, nftAddrExpr("daddr", v6))
		}
		return exprs, nil
	default:
		return nil, fmt.Errorf("rule %s has invalid remote kind %q", rule.ID, rule.Remote.Kind)
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

func nftAddrExpr(field string, addrs []string) string {
	family := "ip"
	if len(addrs) > 0 {
		if addr, ok := parseNodeAddr(addrs[0]); ok && addr.Is6() && !addr.Is4In6() {
			family = "ip6"
		}
	}
	if len(addrs) == 1 {
		return family + " " + field + " " + addrs[0]
	}
	return family + " " + field + " { " + strings.Join(addrs, ", ") + " }"
}

func nodeIPAddrs(node model.Node) ([]string, []string) {
	v4Seen := map[string]struct{}{}
	v6Seen := map[string]struct{}{}
	for _, raw := range []string{node.WireGuardIP, node.PublicIP, node.PublicIPv6} {
		if addr, ok := parseNodeAddr(raw); ok {
			if addr.Is4() {
				v4Seen[addr.String()] = struct{}{}
			} else if addr.Is6() && !addr.Is4In6() {
				v6Seen[addr.String()] = struct{}{}
			}
		}
	}
	v4 := sortedAddrs(v4Seen)
	v6 := sortedAddrs(v6Seen)
	return v4, v6
}

func sortedAddrs(seen map[string]struct{}) []string {
	out := make([]string, 0, len(seen))
	for addr := range seen {
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool {
		return netip.MustParseAddr(out[i]).Compare(netip.MustParseAddr(out[j])) < 0
	})
	return out
}

func parseNodeAddr(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, false
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		addr := prefix.Addr()
		return addr, addr.Is4() || (addr.Is6() && !addr.Is4In6())
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !(addr.Is4() || (addr.Is6() && !addr.Is4In6())) {
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
