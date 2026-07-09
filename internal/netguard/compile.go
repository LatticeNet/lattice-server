package netguard

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

// The compiler LOWERS the guard model into the existing network.NFTPlan rather
// than emitting nft syntax itself. network.GenerateNFTPlan stays the single
// renderer of `table inet lattice_guard`, so byte-for-byte parity with the
// legacy Network Guard path is structural, not a lucky test result, and no
// competing default-drop input hook can appear.
//
// Rule shapes that exactly match the legacy broad-port allows take a fast path
// into the plan's Public*/WireGuard* port lists. Everything else compiles to
// typed network.NFTInputRule values, which the renderer emits BEFORE those
// broad allows — that ordering is what lets a targeted deny override an
// otherwise-open service port. (design-13 §4.4)

// MaxExpandedPortsPerRule bounds range expansion. The current renderer emits
// explicit port lists, so a very wide range would produce an unreadable,
// unreviewable ruleset. Native `from-to` nft range emission is a later
// renderer upgrade (design-13 L2); until then wide ranges fail closed with a
// named error rather than silently exploding the plan.
const MaxExpandedPortsPerRule = 1024

// NodeResolver mirrors netpolicy.NodeResolver so node remotes resolve against
// current fleet state at compile time.
type NodeResolver func(nodeID string) (model.Node, bool)

// CompileInput is the fully-resolved authoring state for one node.
type CompileInput struct {
	Binding model.NodeGuardBinding
	// Groups in binding order. The caller resolves Binding.GroupIDs.
	Groups []model.SecurityGroup
	// Zones by id, including the builtin zones resolved for this node.
	Zones   map[string]model.GuardZone
	Resolve NodeResolver
}

// ErrNodeUnmanaged is returned when a plan is requested for an observe-only
// binding. Converted legacy baselines start unmanaged: an operator must adopt
// a node before its firewall can be planned from the new model.
var ErrNodeUnmanaged = errors.New("node guard binding is observe-only; adopt the node before planning")

// Compile lowers zones, trusted-zone accepts, per-node overrides, and attached
// security groups into a single network.NFTPlan.
func Compile(in CompileInput) (network.NFTPlan, error) {
	if !in.Binding.Managed {
		return network.NFTPlan{}, ErrNodeUnmanaged
	}
	if in.Resolve == nil {
		return network.NFTPlan{}, errors.New("node resolver is required")
	}

	plan := network.NFTPlan{
		InterfaceName: zoneInterface(in.Zones, model.GuardZonePublic, defaultInterface),
		WireGuardCIDR: zoneCIDR(in.Zones, model.GuardZoneWireGuard, defaultWireGuardCIDR),
	}

	// 1. Trusted zones accept first: an overlay the node depends on (tailscale0,
	//    wg0) must never be dropped by the guard it is being protected with.
	for _, zoneID := range in.Binding.ZoneIDs {
		zone, ok := in.Zones[zoneID]
		if !ok {
			return network.NFTPlan{}, fmt.Errorf("trusted zone %q not found", zoneID)
		}
		if zoneID == model.GuardZonePublic {
			return network.NFTPlan{}, errors.New("the public zone cannot be trusted wholesale")
		}
		rules, err := trustedZoneRules(zone)
		if err != nil {
			return network.NFTPlan{}, err
		}
		plan.InputRules = append(plan.InputRules, rules...)
	}

	// 2. Per-node overrides, then 3. attached groups in binding order.
	ordered := make([]model.GuardRule, 0, len(in.Binding.Overrides))
	ordered = append(ordered, in.Binding.Overrides...)
	for _, group := range in.Groups {
		ordered = append(ordered, group.Rules...)
	}

	for _, rule := range ordered {
		if rule.Disabled {
			continue
		}
		if err := lowerRule(&plan, rule, in); err != nil {
			return network.NFTPlan{}, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
	}

	// NormalizeNFTPlan validates/canonicalizes everything and sorts+dedups the
	// fast-path port lists, so two groups contributing the same port union
	// cleanly.
	return network.NormalizeNFTPlan(plan)
}

// CompileRuleset renders the final lattice_guard ruleset for a node.
func CompileRuleset(in CompileInput) (string, error) {
	plan, err := Compile(in)
	if err != nil {
		return "", err
	}
	return network.GenerateNFTPlan(plan)
}

func lowerRule(plan *network.NFTPlan, rule model.GuardRule, in CompileInput) error {
	if rule.Direction != model.NetDirIngress {
		return fmt.Errorf("direction %q is not compiled into the guard table (egress stays with netpolicy)", rule.Direction)
	}
	switch rule.Action {
	case model.NetRuleAllow, model.NetRuleDeny:
	default:
		return fmt.Errorf("invalid action %q", rule.Action)
	}
	switch rule.Protocol {
	case model.NetProtoTCP, model.NetProtoUDP, model.NetProtoAny:
	case model.GuardProtoICMP, model.GuardProtoICMPv6:
		return fmt.Errorf("protocol %q is not supported by the current guard renderer", rule.Protocol)
	default:
		return fmt.Errorf("invalid protocol %q", rule.Protocol)
	}
	if rule.Log {
		return errors.New("log is not supported by the current guard renderer")
	}

	ports, err := ExpandPortRanges(rule.Ports)
	if err != nil {
		return err
	}
	if rule.Protocol == model.NetProtoAny && len(ports) > 0 {
		return errors.New("protocol any cannot carry ports")
	}

	// Fast path: exactly the legacy broad-allow shape. Preserving it is what
	// makes converted legacy baselines render byte-identically.
	if fast := fastPathBucket(plan, rule, ports); fast != nil {
		*fast = append(*fast, ports...)
		return nil
	}

	sources, iface, err := ruleSource(rule, in)
	if err != nil {
		return err
	}
	plan.InputRules = append(plan.InputRules, network.NFTInputRule{
		Interface:   iface,
		SourceCIDRs: sources,
		Protocol:    rule.Protocol,
		Ports:       ports,
		Action:      nftAction(rule.Action),
		Comment:     ruleComment(rule),
	})
	return nil
}

// fastPathBucket returns the plan port list a rule belongs in, or nil when the
// rule needs the general InputRule path. Only the exact legacy shape qualifies:
// an ingress allow, tcp or udp, with at least one port, whose remote is the
// public or wireguard builtin zone. Callers have already rejected the L2
// render features (rate limit, log) and disabled rules.
func fastPathBucket(plan *network.NFTPlan, rule model.GuardRule, ports []int) *[]int {
	if rule.Action != model.NetRuleAllow || len(ports) == 0 {
		return nil
	}
	if rule.Remote.Kind != model.NetRefZone {
		return nil
	}
	switch rule.Remote.ZoneID {
	case model.GuardZonePublic:
		switch rule.Protocol {
		case model.NetProtoTCP:
			return &plan.PublicTCP
		case model.NetProtoUDP:
			return &plan.PublicUDP
		}
	case model.GuardZoneWireGuard:
		switch rule.Protocol {
		case model.NetProtoTCP:
			return &plan.WireGuardTCP
		case model.NetProtoUDP:
			return &plan.WireGuardUDP
		}
	}
	return nil
}

func nftAction(action string) string {
	if action == model.NetRuleDeny {
		return network.NFTActionDrop
	}
	return network.NFTActionAccept
}

func ruleComment(rule model.GuardRule) string {
	if rule.Comment != "" {
		return rule.Comment
	}
	return rule.ID
}

// ruleSource resolves a rule's remote into source CIDRs and/or an inbound
// interface constraint.
func ruleSource(rule model.GuardRule, in CompileInput) ([]string, string, error) {
	switch rule.Remote.Kind {
	case model.NetRefAny, "":
		return nil, "", nil
	case model.NetRefCIDR:
		if rule.Remote.CIDR == "" {
			return nil, "", errors.New("cidr remote requires a cidr")
		}
		return []string{rule.Remote.CIDR}, "", nil
	case model.NetRefNode:
		node, ok := in.Resolve(rule.Remote.NodeID)
		if !ok {
			return nil, "", fmt.Errorf("remote node %q not found", rule.Remote.NodeID)
		}
		sources := nodeSources(node)
		if len(sources) == 0 {
			return nil, "", fmt.Errorf("remote node %q has no resolvable address", rule.Remote.NodeID)
		}
		return sources, "", nil
	case model.NetRefZone:
		zone, ok := in.Zones[rule.Remote.ZoneID]
		if !ok {
			return nil, "", fmt.Errorf("remote zone %q not found", rule.Remote.ZoneID)
		}
		if len(zone.CIDRs) > 0 {
			return append([]string(nil), zone.CIDRs...), "", nil
		}
		if len(zone.Interfaces) == 1 {
			return nil, zone.Interfaces[0], nil
		}
		if len(zone.Interfaces) > 1 {
			return nil, "", fmt.Errorf("zone %q has multiple interfaces; split the rule per interface", zone.ID)
		}
		return nil, "", fmt.Errorf("zone %q resolves to no interface or cidr on this node", zone.ID)
	case model.NetRefDomain:
		return nil, "", errors.New("domain remotes are egress-only")
	case model.NetRefGroup:
		return nil, "", errors.New("group remotes must be expanded to node refs before compile")
	default:
		return nil, "", fmt.Errorf("invalid remote kind %q", rule.Remote.Kind)
	}
}

// nodeSources pins a node remote to its own addresses, mirroring the /32
// AllowedIPs discipline: a node ref can only ever mean that node's addresses.
func nodeSources(node model.Node) []string {
	out := make([]string, 0, 2)
	for _, addr := range []string{node.WireGuardIP, node.PublicIP} {
		if host := hostCIDR(addr); host != "" {
			out = append(out, host)
		}
	}
	return out
}

func hostCIDR(addr string) string {
	host := strings.TrimSpace(addr)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "/") {
		ip, _, err := net.ParseCIDR(host)
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

func trustedZoneRules(zone model.GuardZone) ([]network.NFTInputRule, error) {
	if len(zone.Interfaces) == 0 && len(zone.CIDRs) == 0 {
		return nil, fmt.Errorf("trusted zone %q resolves to no interface or cidr on this node", zone.ID)
	}
	rules := make([]network.NFTInputRule, 0, len(zone.Interfaces)+1)
	for _, iface := range zone.Interfaces {
		rules = append(rules, network.NFTInputRule{
			Interface: iface,
			Protocol:  network.NFTProtoAny,
			Action:    network.NFTActionAccept,
			Comment:   "trusted zone " + zone.ID,
		})
	}
	if len(zone.CIDRs) > 0 {
		rules = append(rules, network.NFTInputRule{
			SourceCIDRs: append([]string(nil), zone.CIDRs...),
			Protocol:    network.NFTProtoAny,
			Action:      network.NFTActionAccept,
			Comment:     "trusted zone " + zone.ID,
		})
	}
	return rules, nil
}

// ExpandPortRanges flattens inclusive ranges into the explicit port list the
// current renderer emits, fail-closed on invalid or excessively wide ranges.
func ExpandPortRanges(ranges []model.GuardPortRange) ([]int, error) {
	if len(ranges) == 0 {
		return nil, nil
	}
	total := 0
	for _, r := range ranges {
		if r.From < 1 || r.From > 65535 || r.To < 1 || r.To > 65535 {
			return nil, fmt.Errorf("invalid port range %d-%d", r.From, r.To)
		}
		if r.From > r.To {
			return nil, fmt.Errorf("inverted port range %d-%d", r.From, r.To)
		}
		total += r.To - r.From + 1
		if total > MaxExpandedPortsPerRule {
			return nil, fmt.Errorf("port ranges expand to more than %d ports; split the rule", MaxExpandedPortsPerRule)
		}
	}
	seen := make(map[int]struct{}, total)
	out := make([]int, 0, total)
	for _, r := range ranges {
		for p := r.From; p <= r.To; p++ {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

func zoneInterface(zones map[string]model.GuardZone, id, fallback string) string {
	if zone, ok := zones[id]; ok && len(zone.Interfaces) > 0 {
		return zone.Interfaces[0]
	}
	return fallback
}

func zoneCIDR(zones map[string]model.GuardZone, id, fallback string) string {
	if zone, ok := zones[id]; ok && len(zone.CIDRs) > 0 {
		return zone.CIDRs[0]
	}
	return fallback
}

// ZoneMap indexes zones by id for CompileInput.
func ZoneMap(zones []model.GuardZone) map[string]model.GuardZone {
	out := make(map[string]model.GuardZone, len(zones))
	for _, zone := range zones {
		out[zone.ID] = zone
	}
	return out
}
