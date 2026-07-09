package netguard

import (
	"errors"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

func noNodes(string) (model.Node, bool) { return model.Node{}, false }

// legacyPlan renders a baseline through the untouched legacy path.
func legacyPlan(t *testing.T, inputs model.NFTInputs) string {
	t.Helper()
	ruleset, err := network.GenerateNFTPlan(network.NFTPlan{
		InterfaceName: inputs.InterfaceName,
		WireGuardCIDR: inputs.WireGuardCIDR,
		PublicTCP:     inputs.PublicTCP,
		PublicUDP:     inputs.PublicUDP,
		WireGuardTCP:  inputs.WireGuardTCP,
		WireGuardUDP:  inputs.WireGuardUDP,
	})
	if err != nil {
		t.Fatalf("legacy render: %v", err)
	}
	return ruleset
}

// convertedPlan renders the same baseline through the design-13 model.
func convertedPlan(t *testing.T, inputs model.NFTInputs, resolve NodeResolver) string {
	t.Helper()
	view := LegacyBaseline(inputs)
	binding := view.Binding
	binding.Managed = true // adoption; conversion itself stays observe-only
	ruleset, err := CompileRuleset(CompileInput{
		Binding: binding,
		Groups:  []model.SecurityGroup{view.Group},
		Zones:   ZoneMap(view.Zones),
		Resolve: resolve,
	})
	if err != nil {
		t.Fatalf("netguard render: %v", err)
	}
	return ruleset
}

// THE PARITY GATE (design-13 §7.1): the converted model must reproduce the
// legacy renderer byte-for-byte before the legacy path may retire. If this
// test ever needs "normalizing" to pass, the migration is unsafe — a firewall
// that silently changes shape is exactly what this design exists to prevent.
func TestLegacyBaselineRendersByteIdentically(t *testing.T) {
	fixtures := []struct {
		name   string
		inputs model.NFTInputs
	}{
		{"empty baseline", model.NFTInputs{NodeID: "n1"}},
		{"public only", model.NFTInputs{
			NodeID: "n2", InterfaceName: "ens3", PublicTCP: []int{80, 443},
		}},
		{"public tcp and udp", model.NFTInputs{
			NodeID: "n3", InterfaceName: "ens3", WireGuardCIDR: "10.66.0.0/24",
			PublicTCP: []int{443, 80, 443}, PublicUDP: []int{53},
		}},
		{"wireguard services", model.NFTInputs{
			NodeID: "n4", WireGuardCIDR: "10.66.0.0/24",
			WireGuardTCP: []int{9100, 22}, WireGuardUDP: []int{51820},
		}},
		{"all four lists", model.NFTInputs{
			NodeID: "n5", InterfaceName: "eth1", WireGuardCIDR: "10.99.0.0/16",
			PublicTCP: []int{22, 443}, PublicUDP: []int{51820},
			WireGuardTCP: []int{9100}, WireGuardUDP: []int{53},
		}},
		{"dmit-eb-wee real baseline", model.NFTInputs{
			NodeID: "dmit-eb-wee", InterfaceName: "eth0", WireGuardCIDR: "10.66.0.0/24",
			PublicTCP: []int{115, 3433, 7443, 7500, 7780, 9009, 9010, 9011, 9012, 9013, 17891, 17893, 42622, 48358, 57289},
			PublicUDP: []int{115, 3433, 7443, 7500, 7780, 9009, 9010, 9011, 9012, 9013, 17891, 17893, 42622, 48358, 57289},
		}},
		{"adjacent run that the converter collapses", model.NFTInputs{
			NodeID: "n6", PublicTCP: []int{9009, 9010, 9011, 9012, 9013},
		}},
		{"unsorted with duplicates", model.NFTInputs{
			NodeID: "n7", PublicTCP: []int{443, 80, 443, 8080},
		}},
	}
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			want := legacyPlan(t, tc.inputs)
			got := convertedPlan(t, tc.inputs, noNodes)
			if got != want {
				t.Fatalf("parity gate broken.\n--- legacy ---\n%s\n--- netguard ---\n%s", want, got)
			}
		})
	}
}

func TestCompileRefusesUnmanagedBinding(t *testing.T) {
	view := LegacyBaseline(model.NFTInputs{NodeID: "n1", PublicTCP: []int{22}})
	_, err := Compile(CompileInput{
		Binding: view.Binding, // Managed=false
		Groups:  []model.SecurityGroup{view.Group},
		Zones:   ZoneMap(view.Zones),
		Resolve: noNodes,
	})
	if !errors.Is(err, ErrNodeUnmanaged) {
		t.Fatalf("err = %v, want ErrNodeUnmanaged", err)
	}
}

// The headline fix: a node that depends on an overlay (tailscale0) can be
// guarded without severing it, and the trusted-zone accept renders before the
// broad public allows.
func TestTrustedZoneRendersIifnameAcceptBeforeBroadAllows(t *testing.T) {
	zones := ZoneMap([]model.GuardZone{
		{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}},
		{ID: model.GuardZoneWireGuard, CIDRs: []string{"10.66.0.0/24"}},
		{ID: model.GuardZoneTailscale, Interfaces: []string{"tailscale0"}},
	})
	ruleset, err := CompileRuleset(CompileInput{
		Binding: model.NodeGuardBinding{
			NodeID:  "n1",
			Managed: true,
			ZoneIDs: []string{model.GuardZoneTailscale},
		},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID: "ssh", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
			Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 22, To: 22}},
			Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
		}}}},
		Zones:   zones,
		Resolve: noNodes,
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted := `iifname "tailscale0" accept comment "trusted zone tailscale"`
	broad := `iifname "eth0" tcp dport { 22 } accept`
	ti, bi := strings.Index(ruleset, trusted), strings.Index(ruleset, broad)
	if ti < 0 {
		t.Fatalf("trusted zone accept missing:\n%s", ruleset)
	}
	if bi < 0 {
		t.Fatalf("public allow missing:\n%s", ruleset)
	}
	if ti > bi {
		t.Fatalf("trusted zone accept must render before broad allows:\n%s", ruleset)
	}
}

func TestCompileRefusesTrustingPublicZone(t *testing.T) {
	_, err := Compile(CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true, ZoneIDs: []string{model.GuardZonePublic}},
		Zones:   ZoneMap([]model.GuardZone{{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}}}),
		Resolve: noNodes,
	})
	if err == nil || !strings.Contains(err.Error(), "public zone cannot be trusted") {
		t.Fatalf("err = %v, want refusal to trust the public zone", err)
	}
}

// A targeted deny must beat an otherwise-open broad service port, which is
// only true because InputRules render before the fast-path allows.
func TestDenyRuleRendersBeforeBroadAllow(t *testing.T) {
	ruleset, err := CompileRuleset(CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{
			{
				ID: "open-1234", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
				Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 1234, To: 1234}},
				Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
			},
			{
				ID: "deny-bad-peer", Action: model.NetRuleDeny, Direction: model.NetDirIngress,
				Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 1234, To: 1234}},
				Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "198.51.100.7/32"},
			},
		}}},
		Zones:   ZoneMap([]model.GuardZone{{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}}}),
		Resolve: noNodes,
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := `ip saddr 198.51.100.7 tcp dport { 1234 } drop`
	allow := `iifname "eth0" tcp dport { 1234 } accept`
	di, ai := strings.Index(ruleset, deny), strings.Index(ruleset, allow)
	if di < 0 || ai < 0 || di > ai {
		t.Fatalf("deny must render before the broad allow:\n%s", ruleset)
	}
}

func TestNodeRemoteResolvesToNodeAddresses(t *testing.T) {
	resolve := func(id string) (model.Node, bool) {
		if id != "peer" {
			return model.Node{}, false
		}
		return model.Node{ID: "peer", WireGuardIP: "10.66.0.2/16", PublicIP: "198.51.100.2"}, true
	}
	ruleset, err := CompileRuleset(CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID: "peer-9100", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
			Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 9100, To: 9100}},
			Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "peer"},
		}}}},
		Zones:   ZoneMap(nil),
		Resolve: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ruleset, `10.66.0.0/16`) || strings.Contains(ruleset, `10.66.0.2/16`) {
		t.Fatalf("node remote must not preserve a peer-advertised wide prefix:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, `ip saddr { 10.66.0.2, 198.51.100.2 } tcp dport { 9100 } accept`) {
		t.Fatalf("node remote did not resolve to both addresses:\n%s", ruleset)
	}

	if _, err := CompileRuleset(CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID: "ghost", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
			Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 1, To: 1}},
			Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "missing"},
		}}}},
		Zones:   ZoneMap(nil),
		Resolve: resolve,
	}); err == nil {
		t.Fatal("unknown node remote must be rejected, never silently widened")
	}
}

func TestCompileFailsClosedOnUnsupportedShapes(t *testing.T) {
	base := func(rule model.GuardRule) error {
		_, err := Compile(CompileInput{
			Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true},
			Groups:  []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{rule}}},
			Zones:   ZoneMap([]model.GuardZone{{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}}}),
			Resolve: noNodes,
		})
		return err
	}
	pub := model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic}
	p80 := []model.GuardPortRange{{From: 80, To: 80}}

	cases := []struct {
		name string
		rule model.GuardRule
		want string
	}{
		{"egress direction", model.GuardRule{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: p80, Remote: pub}, "not compiled into the guard table"},
		{"icmp", model.GuardRule{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.GuardProtoICMP, Remote: pub}, "not supported by the current guard renderer"},
		{"log", model.GuardRule{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: p80, Remote: pub, Log: true}, "log is not supported"},
		{"domain remote", model.GuardRule{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: p80, Remote: model.NetEndpoint{Kind: model.NetRefDomain, Domain: "x.example"}}, "egress-only"},
		{"group remote", model.GuardRule{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: p80, Remote: model.NetEndpoint{Kind: model.NetRefGroup, GroupID: "g"}}, "expanded to node refs"},
		{"bad action", model.GuardRule{ID: "r", Action: "maybe", Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: p80, Remote: pub}, "invalid action"},
		{"any protocol with ports", model.GuardRule{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoAny, Ports: p80, Remote: pub}, "cannot carry ports"},
		{"unknown zone", model.GuardRule{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: p80, Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: "ghost"}}, "not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := base(tc.rule)
			if err == nil {
				t.Fatal("want fail-closed error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestDisabledRulesAreSkipped(t *testing.T) {
	plan, err := Compile(CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID: "off", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
			Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 80, To: 80}},
			Remote:   model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
			Disabled: true,
		}}}},
		Zones:   ZoneMap([]model.GuardZone{{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}}}),
		Resolve: noNodes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.PublicTCP) != 0 {
		t.Fatalf("disabled rule leaked into the plan: %v", plan.PublicTCP)
	}
}

func TestOverridesRenderBeforeGroupRules(t *testing.T) {
	ruleset, err := CompileRuleset(CompileInput{
		Binding: model.NodeGuardBinding{
			NodeID: "n1", Managed: true,
			Overrides: []model.GuardRule{{
				ID: "override-deny", Action: model.NetRuleDeny, Direction: model.NetDirIngress,
				Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 80, To: 80}},
				Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "203.0.113.0/24"},
			}},
		},
		Groups: []model.SecurityGroup{{ID: "sg", Rules: []model.GuardRule{{
			ID: "group-deny", Action: model.NetRuleDeny, Direction: model.NetDirIngress,
			Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 80, To: 80}},
			Remote: model.NetEndpoint{Kind: model.NetRefCIDR, CIDR: "198.51.100.0/24"},
		}}}},
		Zones:   ZoneMap(nil),
		Resolve: noNodes,
	})
	if err != nil {
		t.Fatal(err)
	}
	oi := strings.Index(ruleset, "203.0.113.0/24")
	gi := strings.Index(ruleset, "198.51.100.0/24")
	if oi < 0 || gi < 0 || oi > gi {
		t.Fatalf("node overrides must render before group rules:\n%s", ruleset)
	}
}

func TestExpandPortRanges(t *testing.T) {
	got, err := ExpandPortRanges([]model.GuardPortRange{{From: 9009, To: 9013}, {From: 22, To: 22}})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 9009, 9010, 9011, 9012, 9013}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	if _, err := ExpandPortRanges([]model.GuardPortRange{{From: 5, To: 1}}); err == nil {
		t.Fatal("inverted range must fail closed")
	}
	if _, err := ExpandPortRanges([]model.GuardPortRange{{From: 0, To: 10}}); err == nil {
		t.Fatal("out-of-range port must fail closed")
	}
	if _, err := ExpandPortRanges([]model.GuardPortRange{{From: 1, To: 65535}}); err == nil {
		t.Fatal("excessively wide range must fail closed rather than explode the ruleset")
	}
}

func TestLintLockoutRisk(t *testing.T) {
	pub := model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic}
	zones := ZoneMap([]model.GuardZone{
		{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}},
		{ID: model.GuardZoneTailscale, Interfaces: []string{"tailscale0"}},
	})
	compile := func(binding model.NodeGuardBinding, rules []model.GuardRule) network.NFTPlan {
		t.Helper()
		binding.Managed = true
		plan, err := Compile(CompileInput{
			Binding: binding,
			Groups:  []model.SecurityGroup{{ID: "sg", Rules: rules}},
			Zones:   zones,
			Resolve: noNodes,
		})
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}

	// The dmit-eb-wee shape: 15 public ports, none of them 22.
	risky := compile(model.NodeGuardBinding{NodeID: "n1"}, []model.GuardRule{{
		ID: "svc", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
		Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 7443, To: 7443}},
		Remote: pub,
	}})
	findings := Lint(risky, LintOptions{PublicURLConfigured: true})
	if !Blocking(findings) {
		t.Fatalf("a plan with no tcp/22 accept must block: %+v", findings)
	}
	if findings[0].Code != FindingLockoutRiskSSH {
		t.Fatalf("finding = %+v", findings[0])
	}

	// Allowing tcp/22 clears it.
	safe := compile(model.NodeGuardBinding{NodeID: "n1"}, []model.GuardRule{{
		ID: "ssh", Action: model.NetRuleAllow, Direction: model.NetDirIngress,
		Protocol: model.NetProtoTCP, Ports: []model.GuardPortRange{{From: 22, To: 22}},
		Remote: pub,
	}})
	if Blocking(Lint(safe, LintOptions{PublicURLConfigured: true})) {
		t.Fatal("a plan that accepts tcp/22 must not block")
	}

	// So does trusting an overlay zone that still reaches the node.
	viaOverlay := compile(model.NodeGuardBinding{NodeID: "n1", ZoneIDs: []string{model.GuardZoneTailscale}}, nil)
	if Blocking(Lint(viaOverlay, LintOptions{PublicURLConfigured: true})) {
		t.Fatal("a trusted overlay zone must satisfy the management-path lint")
	}
}

func TestLintUnverifiedApplyWarnsButDoesNotBlock(t *testing.T) {
	plan := network.NFTPlan{PublicTCP: []int{22}}
	findings := Lint(plan, LintOptions{PublicURLConfigured: false})
	if Blocking(findings) {
		t.Fatal("missing public url must warn, not block")
	}
	if len(findings) != 1 || findings[0].Code != FindingUnverifiedApply {
		t.Fatalf("findings = %+v", findings)
	}
}
