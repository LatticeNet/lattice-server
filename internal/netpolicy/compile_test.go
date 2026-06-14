package netpolicy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestCompileEgressRulesetRendersDeterministicPolicy(t *testing.T) {
	nodes := map[string]model.Node{
		"node-a": {ID: "node-a", Name: "A", WireGuardIP: "10.66.0.1/32", PublicIP: "203.0.113.10"},
		"node-b": {ID: "node-b", Name: "B", WireGuardIP: "10.66.0.2/32", PublicIP: "198.51.100.2"},
	}
	policy := model.NetPolicy{
		TargetNodeID: "node-a",
		Enabled:      true,
		Rules: []model.NetRule{
			{
				ID:        "deny-db",
				Comment:   `db "quoted"`,
				Action:    model.NetRuleDeny,
				Direction: model.NetDirEgress,
				Protocol:  model.NetProtoTCP,
				Ports:     []int{1234, 22},
				Remote:    model.NetEndpoint{Kind: model.NetRefNode, NodeID: "node-b"},
			},
			{
				ID:        "allow-metrics",
				Action:    model.NetRuleAllow,
				Direction: model.NetDirEgress,
				Protocol:  model.NetProtoUDP,
				Ports:     []int{9100},
				Remote:    model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "192.0.2.0/24"},
			},
		},
	}
	got, err := CompileEgressRuleset(policy, func(id string) (model.Node, bool) {
		n, ok := nodes[id]
		return n, ok
	}, CompileOptions{ControlPlaneIPv4: netip.MustParseAddr("203.0.113.99"), ControlPlanePort: 443})
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"destroy table inet lattice_policy",
		"table inet lattice_policy",
		"ct state established,related accept",
		"oifname \"lo\" accept",
		"ip daddr 203.0.113.99 tcp dport 443 accept comment \"lattice control-plane\"",
		"udp dport 53 accept comment \"lattice dns udp\"",
		"tcp dport 53 accept comment \"lattice dns tcp\"",
		"ip daddr { 10.66.0.2, 198.51.100.2 } tcp dport { 22, 1234 } drop comment \"lattice rule deny-db db \\\"quoted\\\"\"",
		"ip daddr 192.0.2.0/24 udp dport 9100 accept comment \"lattice rule allow-metrics\"",
		"counter drop comment \"lattice default drop\"",
	} {
		if !strings.Contains(got, needle) {
			t.Fatalf("compiled ruleset missing %q:\n%s", needle, got)
		}
	}
	if strings.Index(got, "lattice control-plane") > strings.Index(got, "deny-db") {
		t.Fatalf("control-plane allow must be emitted before operator rules:\n%s", got)
	}
}

func TestCompileEgressRulesetRejectsIngress(t *testing.T) {
	_, err := CompileEgressRuleset(model.NetPolicy{
		TargetNodeID: "node-a",
		Enabled:      true,
		Rules: []model.NetRule{{
			ID:        "ingress",
			Action:    model.NetRuleAllow,
			Direction: model.NetDirIngress,
			Protocol:  model.NetProtoTCP,
			Ports:     []int{22},
			Remote:    model.NetEndpoint{Kind: model.NetRefAny},
		}},
	}, func(id string) (model.Node, bool) {
		return model.Node{ID: id, WireGuardIP: "10.66.0.1"}, true
	}, CompileOptions{ControlPlaneIPv4: netip.MustParseAddr("203.0.113.99"), ControlPlanePort: 443})
	if err == nil || !strings.Contains(err.Error(), "egress-only") {
		t.Fatalf("expected egress-only error, got %v", err)
	}
}

func TestCompileEgressRulesetRejectsNodeWithoutIPv4(t *testing.T) {
	nodes := map[string]model.Node{
		"node-a": {ID: "node-a", WireGuardIP: "10.66.0.1"},
		"node-b": {ID: "node-b", PublicIPv6: "2001:db8::2"},
	}
	_, err := CompileEgressRuleset(model.NetPolicy{
		TargetNodeID: "node-a",
		Enabled:      true,
		Rules: []model.NetRule{{
			ID:        "deny-node-b",
			Action:    model.NetRuleDeny,
			Direction: model.NetDirEgress,
			Protocol:  model.NetProtoTCP,
			Ports:     []int{443},
			Remote:    model.NetEndpoint{Kind: model.NetRefNode, NodeID: "node-b"},
		}},
	}, func(id string) (model.Node, bool) {
		n, ok := nodes[id]
		return n, ok
	}, CompileOptions{ControlPlaneIPv4: netip.MustParseAddr("203.0.113.99"), ControlPlanePort: 443})
	if err == nil || !strings.Contains(err.Error(), "no IPv4 address") {
		t.Fatalf("expected no IPv4 error, got %v", err)
	}
}
