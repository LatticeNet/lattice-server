package netpolicy

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestNormalizePolicyCanonicalizesRules(t *testing.T) {
	policy, err := NormalizePolicy(model.NetPolicy{
		TargetNodeID: "node-a",
		Enabled:      true,
		Rules: []model.NetRule{{
			Comment:   " deny db\n",
			Action:    model.NetRuleDeny,
			Direction: model.NetDirEgress,
			Protocol:  model.NetProtoTCP,
			Ports:     []int{1234, 22, 1234},
			Remote:    model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "192.0.2.9/24"},
		}},
	}, testResolver("node-a"))
	if err != nil {
		t.Fatal(err)
	}
	if policy.ID != "node-a" || policy.Rules[0].ID != "rule_001" {
		t.Fatalf("ids not normalized: %+v", policy)
	}
	if policy.Rules[0].Comment != "deny db" {
		t.Fatalf("comment not sanitized: %q", policy.Rules[0].Comment)
	}
	if got := policy.Rules[0].Remote.CIDR; got != "192.0.2.0/24" {
		t.Fatalf("cidr = %q", got)
	}
	if got := policy.Rules[0].Ports; len(got) != 2 || got[0] != 22 || got[1] != 1234 {
		t.Fatalf("ports = %+v", got)
	}
}

func TestNormalizePolicyRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name   string
		policy model.NetPolicy
	}{
		{name: "missing target", policy: model.NetPolicy{}},
		{name: "unknown target", policy: model.NetPolicy{TargetNodeID: "missing"}},
		{name: "unknown remote node", policy: basePolicy(model.NetEndpoint{Kind: model.NetRefNode, NodeID: "missing"}, model.NetProtoTCP, []int{22})},
		{name: "bad cidr", policy: basePolicy(model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "not-a-cidr"}, model.NetProtoTCP, []int{22})},
		{name: "bad port", policy: basePolicy(model.NetEndpoint{Kind: model.NetRefAny}, model.NetProtoTCP, []int{70000})},
		{name: "any with ports", policy: basePolicy(model.NetEndpoint{Kind: model.NetRefAny}, model.NetProtoAny, []int{53})},
		{name: "duplicate rule id", policy: model.NetPolicy{
			TargetNodeID: "node-a",
			Enabled:      true,
			Rules: []model.NetRule{
				{ID: "same", Action: model.NetRuleDeny, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: []int{22}, Remote: model.NetEndpoint{Kind: model.NetRefAny}},
				{ID: "same", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefAny}},
			},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NormalizePolicy(tc.policy, testResolver("node-a", "node-b")); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestNormalizePolicyCanonicalizesIPv6CIDR(t *testing.T) {
	policy, err := NormalizePolicy(model.NetPolicy{
		TargetNodeID: "node-a",
		Enabled:      true,
		Rules: []model.NetRule{{
			ID:        "deny-v6",
			Action:    model.NetRuleDeny,
			Direction: model.NetDirEgress,
			Protocol:  model.NetProtoTCP,
			Ports:     []int{443},
			Remote:    model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "2001:db8::1/32"},
		}},
	}, testResolver("node-a"))
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.Rules[0].Remote.CIDR; got != "2001:db8::/32" {
		t.Fatalf("ipv6 cidr = %q", got)
	}
}

func TestBuildGraphDerivesEdgesAndExternals(t *testing.T) {
	policy, err := NormalizePolicy(model.NetPolicy{
		TargetNodeID: "node-a",
		Enabled:      true,
		Rules: []model.NetRule{
			{ID: "deny-db", Action: model.NetRuleDeny, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: []int{1234}, Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "node-b"}},
			{ID: "allow-dns", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: model.NetProtoUDP, Ports: []int{53}, Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "1.1.1.1"}},
		},
	}, testResolver("node-a", "node-b"))
	if err != nil {
		t.Fatal(err)
	}
	graph := BuildGraph([]model.Node{{ID: "node-b", Name: "B"}, {ID: "node-a", Name: "A", Online: true}}, []model.NetPolicy{policy})
	if len(graph.Nodes) != 2 || graph.Nodes[0].ID != "node-a" {
		t.Fatalf("nodes not sorted: %+v", graph.Nodes)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].From != "node-a" || graph.Edges[0].To != "node-b" || graph.Edges[0].Action != model.NetRuleDeny {
		t.Fatalf("bad edges: %+v", graph.Edges)
	}
	if len(graph.Externals) != 1 || graph.Externals[0].Remote != "1.1.1.1" || graph.Externals[0].Ports[0] != 53 {
		t.Fatalf("bad externals: %+v", graph.Externals)
	}
}

func basePolicy(remote model.NetEndpoint, proto string, ports []int) model.NetPolicy {
	return model.NetPolicy{
		TargetNodeID: "node-a",
		Enabled:      true,
		Rules: []model.NetRule{{
			Action:    model.NetRuleDeny,
			Direction: model.NetDirEgress,
			Protocol:  proto,
			Ports:     ports,
			Remote:    remote,
		}},
	}
}

func testResolver(ids ...string) NodeResolver {
	nodes := map[string]model.Node{}
	for _, id := range ids {
		nodes[id] = model.Node{ID: id, Name: id}
	}
	return func(id string) (model.Node, bool) {
		node, ok := nodes[id]
		return node, ok
	}
}
