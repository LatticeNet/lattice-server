package netpolicy

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestExpandGroupPoliciesGroupRemoteFanout(t *testing.T) {
	resolved := map[string][]string{
		"g-web": {"n1", "n2"},
		"g-db":  {"n3", "n4"},
	}
	policies := []model.GroupNetPolicy{{
		ID:           "gnp_1",
		ScopeGroupID: "g-web",
		Enabled:      true,
		Rules: []model.GroupNetRule{{
			ID:        "r1",
			Action:    "allow",
			Direction: "egress",
			Protocol:  "tcp",
			Ports:     []int{5432},
			Remote:    model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "g-db"},
		}},
	}}

	out := ExpandGroupPolicies(policies, resolved)
	// Both web members get policies; each fans the g-db remote to n3 and n4.
	for _, target := range []string{"n1", "n2"} {
		np, ok := out[target]
		if !ok {
			t.Fatalf("expected policy for %s", target)
		}
		if !np.GroupDerived || np.TargetNodeID != target || !np.Enabled {
			t.Fatalf("bad policy header for %s: %+v", target, np)
		}
		if len(np.Rules) != 2 {
			t.Fatalf("%s: expected 2 fanned rules, got %d", target, len(np.Rules))
		}
		for _, rule := range np.Rules {
			if rule.Remote.Kind != model.NetRefNode || (rule.Remote.NodeID != "n3" && rule.Remote.NodeID != "n4") {
				t.Fatalf("%s: expected node remote n3/n4, got %+v", target, rule.Remote)
			}
		}
	}
	if _, ok := out["n3"]; ok {
		t.Fatal("db nodes are not in scope group g-web; should have no policy")
	}
}

func TestExpandSkipsSelfRef(t *testing.T) {
	resolved := map[string][]string{"g": {"n1", "n2"}}
	policies := []model.GroupNetPolicy{{
		ID: "gnp_self", ScopeGroupID: "g", Enabled: true,
		Rules: []model.GroupNetRule{{
			ID: "r", Action: "allow", Direction: "egress", Protocol: "any",
			Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "g"}, // intra-group
		}},
	}}
	out := ExpandGroupPolicies(policies, resolved)
	// n1 should get a rule to n2 only (not to itself); likewise n2 -> n1.
	if len(out["n1"].Rules) != 1 || out["n1"].Rules[0].Remote.NodeID != "n2" {
		t.Fatalf("n1 self-ref not skipped: %+v", out["n1"].Rules)
	}
	if len(out["n2"].Rules) != 1 || out["n2"].Rules[0].Remote.NodeID != "n1" {
		t.Fatalf("n2 self-ref not skipped: %+v", out["n2"].Rules)
	}
}

func TestExpandMultiPolicyPriorityUnion(t *testing.T) {
	resolved := map[string][]string{"g": {"n1"}}
	policies := []model.GroupNetPolicy{
		{ID: "gnp_b", ScopeGroupID: "g", Enabled: true, Priority: 10, Rules: []model.GroupNetRule{{ID: "low", Action: "allow", Direction: "egress", Protocol: "tcp", Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "10.0.0.0/8"}}}},
		{ID: "gnp_a", ScopeGroupID: "g", Enabled: true, Priority: 1, Rules: []model.GroupNetRule{{ID: "high", Action: "deny", Direction: "egress", Protocol: "any", Remote: model.NetEndpoint{Kind: model.NetRefAny}}}},
	}
	out := ExpandGroupPolicies(policies, resolved)
	np := out["n1"]
	if len(np.Rules) != 2 {
		t.Fatalf("expected union of 2 rules, got %d", len(np.Rules))
	}
	// Lower Priority wins ordering: gnp_a (priority 1) rule comes first.
	if np.Rules[0].ID != "high" || np.Rules[1].ID != "low" {
		t.Fatalf("priority ordering wrong: %s then %s", np.Rules[0].ID, np.Rules[1].ID)
	}
}

func TestExpandDropsDisabledAndPassesThroughNonGroup(t *testing.T) {
	resolved := map[string][]string{"g": {"n1"}}
	policies := []model.GroupNetPolicy{{
		ID: "gnp", ScopeGroupID: "g", Enabled: true,
		Rules: []model.GroupNetRule{
			{ID: "off", Disabled: true, Action: "allow", Remote: model.NetEndpoint{Kind: model.NetRefAny}},
			{ID: "cidr", Action: "allow", Direction: "egress", Protocol: "tcp", Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "1.1.1.1/32"}},
		},
	}}
	out := ExpandGroupPolicies(policies, resolved)
	np := out["n1"]
	if len(np.Rules) != 1 || np.Rules[0].ID != "cidr" || np.Rules[0].Remote.CIDR != "1.1.1.1/32" {
		t.Fatalf("expected only the cidr rule passed through, got %+v", np.Rules)
	}
}

func TestExpandDisabledPolicyAndEmptyScope(t *testing.T) {
	resolved := map[string][]string{"g": {"n1"}, "empty": {}}
	policies := []model.GroupNetPolicy{
		{ID: "off", ScopeGroupID: "g", Enabled: false, Rules: []model.GroupNetRule{{ID: "x", Remote: model.NetEndpoint{Kind: model.NetRefAny}}}},
		{ID: "empty", ScopeGroupID: "empty", Enabled: true, Rules: []model.GroupNetRule{{ID: "y", Remote: model.NetEndpoint{Kind: model.NetRefAny}}}},
	}
	out := ExpandGroupPolicies(policies, resolved)
	if len(out) != 0 {
		t.Fatalf("disabled policy + empty-scope policy should yield nothing, got %v", out)
	}
}
