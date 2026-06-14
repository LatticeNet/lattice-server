package netpolicy

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
)

type NodeResolver func(id string) (model.Node, bool)

type Graph struct {
	Nodes     []GraphNode     `json:"nodes"`
	Edges     []GraphEdge     `json:"edges"`
	Externals []GraphExternal `json:"externals"`
}

type GraphNode struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Online bool           `json:"online"`
	Geo    *model.NodeGeo `json:"geo,omitempty"`
}

type GraphEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	Ports     []int  `json:"ports,omitempty"`
	Direction string `json:"direction"`
	RuleID    string `json:"rule_id"`
}

type GraphExternal struct {
	TargetNodeID string `json:"target_node_id"`
	Action       string `json:"action"`
	Remote       string `json:"remote"`
	Protocol     string `json:"protocol"`
	Ports        []int  `json:"ports,omitempty"`
	Direction    string `json:"direction"`
	RuleID       string `json:"rule_id"`
}

func NormalizePolicy(policy model.NetPolicy, resolve NodeResolver) (model.NetPolicy, error) {
	policy.TargetNodeID = strings.TrimSpace(policy.TargetNodeID)
	if policy.TargetNodeID == "" {
		return model.NetPolicy{}, errors.New("target_node_id is required")
	}
	if resolve == nil {
		return model.NetPolicy{}, errors.New("node resolver is required")
	}
	if _, ok := resolve(policy.TargetNodeID); !ok {
		return model.NetPolicy{}, fmt.Errorf("target node %q not found", policy.TargetNodeID)
	}
	policy.ID = policy.TargetNodeID
	normalized := make([]model.NetRule, 0, len(policy.Rules))
	seenRuleIDs := map[string]struct{}{}
	for i, rule := range policy.Rules {
		r, err := normalizeRule(i, rule, resolve)
		if err != nil {
			return model.NetPolicy{}, err
		}
		if _, ok := seenRuleIDs[r.ID]; ok {
			return model.NetPolicy{}, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seenRuleIDs[r.ID] = struct{}{}
		normalized = append(normalized, r)
	}
	policy.Rules = normalized
	return policy, nil
}

func BuildGraph(nodes []model.Node, policies []model.NetPolicy) Graph {
	nodeByID := map[string]model.Node{}
	graph := Graph{
		Nodes: make([]GraphNode, 0, len(nodes)),
	}
	for _, node := range nodes {
		nodeByID[node.ID] = node
		graph.Nodes = append(graph.Nodes, GraphNode{ID: node.ID, Name: node.Name, Online: node.Online, Geo: node.Geo})
	}
	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].ID < graph.Nodes[j].ID })
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if _, ok := nodeByID[policy.TargetNodeID]; !ok {
			continue
		}
		for _, rule := range policy.Rules {
			if rule.Disabled {
				continue
			}
			switch rule.Remote.Kind {
			case model.NetRefNode:
				if _, ok := nodeByID[rule.Remote.NodeID]; !ok {
					continue
				}
				from, to := policy.TargetNodeID, rule.Remote.NodeID
				if rule.Direction == model.NetDirIngress {
					from, to = rule.Remote.NodeID, policy.TargetNodeID
				}
				graph.Edges = append(graph.Edges, GraphEdge{
					From: from, To: to, Action: rule.Action, Protocol: rule.Protocol,
					Ports: append([]int(nil), rule.Ports...), Direction: rule.Direction, RuleID: rule.ID,
				})
			case model.NetRefCIDR:
				graph.Externals = append(graph.Externals, externalForRule(policy.TargetNodeID, rule, rule.Remote.CIDR))
			case model.NetRefAny:
				graph.Externals = append(graph.Externals, externalForRule(policy.TargetNodeID, rule, "any"))
			}
		}
	}
	sort.Slice(graph.Edges, func(i, j int) bool {
		if graph.Edges[i].From == graph.Edges[j].From {
			return graph.Edges[i].To < graph.Edges[j].To
		}
		return graph.Edges[i].From < graph.Edges[j].From
	})
	sort.Slice(graph.Externals, func(i, j int) bool {
		if graph.Externals[i].TargetNodeID == graph.Externals[j].TargetNodeID {
			return graph.Externals[i].Remote < graph.Externals[j].Remote
		}
		return graph.Externals[i].TargetNodeID < graph.Externals[j].TargetNodeID
	})
	return graph
}

func externalForRule(target string, rule model.NetRule, remote string) GraphExternal {
	return GraphExternal{
		TargetNodeID: target,
		Action:       rule.Action,
		Remote:       remote,
		Protocol:     rule.Protocol,
		Ports:        append([]int(nil), rule.Ports...),
		Direction:    rule.Direction,
		RuleID:       rule.ID,
	}
}

func normalizeRule(index int, rule model.NetRule, resolve NodeResolver) (model.NetRule, error) {
	if strings.TrimSpace(rule.ID) == "" {
		rule.ID = fmt.Sprintf("rule_%03d", index+1)
	} else {
		rule.ID = sanitizeToken(rule.ID, 64)
	}
	rule.Comment = sanitizeComment(rule.Comment, 160)
	if !oneOf(rule.Action, model.NetRuleAllow, model.NetRuleDeny) {
		return model.NetRule{}, fmt.Errorf("rule %s has invalid action %q", rule.ID, rule.Action)
	}
	if !oneOf(rule.Direction, model.NetDirEgress, model.NetDirIngress) {
		return model.NetRule{}, fmt.Errorf("rule %s has invalid direction %q", rule.ID, rule.Direction)
	}
	if !oneOf(rule.Protocol, model.NetProtoTCP, model.NetProtoUDP, model.NetProtoAny) {
		return model.NetRule{}, fmt.Errorf("rule %s has invalid protocol %q", rule.ID, rule.Protocol)
	}
	ports, err := normalizePorts(rule.Ports)
	if err != nil {
		return model.NetRule{}, fmt.Errorf("rule %s ports: %w", rule.ID, err)
	}
	if rule.Protocol == model.NetProtoAny && len(ports) > 0 {
		return model.NetRule{}, fmt.Errorf("rule %s protocol any cannot carry ports", rule.ID)
	}
	rule.Ports = ports
	remote, err := normalizeEndpoint(rule.Remote, resolve)
	if err != nil {
		return model.NetRule{}, fmt.Errorf("rule %s remote: %w", rule.ID, err)
	}
	rule.Remote = remote
	return rule, nil
}

func normalizeEndpoint(endpoint model.NetEndpoint, resolve NodeResolver) (model.NetEndpoint, error) {
	endpoint.Kind = strings.TrimSpace(endpoint.Kind)
	switch endpoint.Kind {
	case model.NetRefNode:
		endpoint.NodeID = strings.TrimSpace(endpoint.NodeID)
		if endpoint.NodeID == "" {
			return model.NetEndpoint{}, errors.New("node_id is required")
		}
		if _, ok := resolve(endpoint.NodeID); !ok {
			return model.NetEndpoint{}, fmt.Errorf("node %q not found", endpoint.NodeID)
		}
		endpoint.CIDR = ""
	case model.NetRefCIDR:
		cidr, err := normalizeIPCIDR(endpoint.CIDR)
		if err != nil {
			return model.NetEndpoint{}, err
		}
		endpoint.CIDR = cidr
		endpoint.NodeID = ""
	case model.NetRefAny:
		endpoint.NodeID = ""
		endpoint.CIDR = ""
	default:
		return model.NetEndpoint{}, fmt.Errorf("invalid kind %q", endpoint.Kind)
	}
	return endpoint, nil
}

func normalizeIPCIDR(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("cidr is required")
	}
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
		return "", fmt.Errorf("invalid cidr %q", value)
	}
	if ip.To4() != nil && ipNet.IP.To4() != nil {
		return ipNet.String(), nil
	}
	if ip.To16() != nil && ip.To4() == nil && ipNet.IP.To16() != nil {
		return ipNet.String(), nil
	}
	return "", fmt.Errorf("invalid cidr %q", value)
}

func normalizePorts(values []int) ([]int, error) {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(values))
	for _, p := range values {
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

func oneOf(value string, allowed ...string) bool {
	for _, v := range allowed {
		if value == v {
			return true
		}
	}
	return false
}

func sanitizeToken(value string, max int) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	if b.Len() == 0 {
		return "rule"
	}
	return b.String()
}

func sanitizeComment(value string, max int) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		if r == '\n' || r == '\r' || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	return b.String()
}
