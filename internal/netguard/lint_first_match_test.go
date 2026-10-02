package netguard

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

// The guard chain is evaluated first match wins, and the group editor offers
// deny. A drop on the management port rendered ahead of the accept that was
// supposed to keep the operator's shell reachable used to pass the lockout
// lint with no finding at all, because the scan skipped every rule that was
// not an accept. These tests pin the walk in evaluation order.

// sshdOnEth0 is a node that reports sshd on tcp/22 and the eth0 interface, so
// only the management-port check is exercised.
func sshdOnEth0() *model.GuardNodeReality {
	r := realityWithSSH(22, "sshd(701)", "0.0.0.0")
	r.Interfaces = []model.GuardInterface{{Name: "eth0", Up: true}, {Name: "wg0", Up: true}}
	return r
}

func lockoutFinding(t *testing.T, plan network.NFTPlan) (Finding, bool) {
	t.Helper()
	f, ok := codes(Lint(plan, LintOptions{PublicURLConfigured: true, Reality: sshdOnEth0()}))[FindingLockoutRiskSSH]
	return f, ok
}

func TestLintBlocksADropAheadOfThePublicManagementAccept(t *testing.T) {
	plan := network.NFTPlan{
		InterfaceName: "eth0",
		InputRules: []network.NFTInputRule{{
			Protocol: network.NFTProtoTCP, Ports: []int{22}, Action: network.NFTActionDrop, Comment: "deny-ssh",
		}},
		PublicTCP: []int{22, 443},
	}
	finding, ok := lockoutFinding(t, plan)
	if !ok || finding.Severity != SeverityBlock {
		t.Fatalf("a drop on tcp/22 ahead of the public tcp/22 accept must block, got %+v", Lint(plan, LintOptions{PublicURLConfigured: true, Reality: sshdOnEth0()}))
	}
	if !strings.Contains(finding.Message, `"deny-ssh"`) || !strings.Contains(finding.Message, "first") {
		t.Fatalf("the finding must name the drop that shadows the accept and say why: %s", finding.Message)
	}
}

func TestLintBlocksAnAnyProtocolDropAheadOfEveryAccept(t *testing.T) {
	plan := network.NFTPlan{
		InterfaceName: "eth0",
		InputRules: []network.NFTInputRule{
			{Protocol: network.NFTProtoAny, Action: network.NFTActionDrop, Comment: "drop-everything"},
			{Protocol: network.NFTProtoTCP, Ports: []int{22}, Action: network.NFTActionAccept, Comment: "ssh"},
		},
		WireGuardTCP: []int{22},
	}
	if _, ok := lockoutFinding(t, plan); !ok {
		t.Fatal("an unconditional drop ahead of every accept must block")
	}
}

// One surviving path is still enough, as before: the walk only changes what
// counts as a path, never the "no way in" question.
func TestLintKeepsAManagementPathTheDropDoesNotCover(t *testing.T) {
	cases := map[string]network.NFTPlan{
		"the drop comes after the accept": {
			InterfaceName: "eth0",
			InputRules: []network.NFTInputRule{
				{Protocol: network.NFTProtoTCP, Ports: []int{22}, Interface: "eth0", Action: network.NFTActionAccept, Comment: "ssh"},
				{Protocol: network.NFTProtoTCP, Ports: []int{22}, Action: network.NFTActionDrop, Comment: "deny-ssh"},
			},
		},
		"the drop names one source and the accept takes every source": {
			InterfaceName: "eth0",
			InputRules: []network.NFTInputRule{{
				Protocol: network.NFTProtoTCP, Ports: []int{22}, SourceCIDRs: []string{"198.51.100.7/32"},
				Action: network.NFTActionDrop, Comment: "deny-bad-peer",
			}},
			PublicTCP: []int{22},
		},
		"the drop is on another interface": {
			InterfaceName: "eth0",
			InputRules: []network.NFTInputRule{{
				Protocol: network.NFTProtoTCP, Ports: []int{22}, Interface: "wg0",
				Action: network.NFTActionDrop, Comment: "deny-overlay-ssh",
			}},
			PublicTCP: []int{22},
		},
		"the drop is udp": {
			InterfaceName: "eth0",
			InputRules: []network.NFTInputRule{{
				Protocol: network.NFTProtoUDP, Ports: []int{22}, Action: network.NFTActionDrop, Comment: "deny-udp",
			}},
			PublicTCP: []int{22},
		},
		"the drop is on the public interface and the wireguard accept is not": {
			InterfaceName: "eth0",
			InputRules: []network.NFTInputRule{{
				Protocol: network.NFTProtoTCP, Ports: []int{22}, Interface: "eth0",
				Action: network.NFTActionDrop, Comment: "no-public-ssh",
			}},
			PublicTCP:    []int{22},
			WireGuardTCP: []int{22},
		},
		"the drop covers a narrower source range than the accept": {
			InterfaceName: "eth0",
			InputRules: []network.NFTInputRule{
				{Protocol: network.NFTProtoTCP, Ports: []int{22}, SourceCIDRs: []string{"203.0.113.0/25"}, Action: network.NFTActionDrop, Comment: "deny-half"},
				{Protocol: network.NFTProtoTCP, Ports: []int{22}, SourceCIDRs: []string{"203.0.113.0/24"}, Action: network.NFTActionAccept, Comment: "office"},
			},
		},
	}
	for name, plan := range cases {
		t.Run(name, func(t *testing.T) {
			if f, ok := lockoutFinding(t, plan); ok {
				t.Fatalf("a management path survives, so the lint must not block: %+v", f)
			}
		})
	}
}

func TestLintBlocksADropThatCoversTheAcceptsSources(t *testing.T) {
	plan := network.NFTPlan{
		InterfaceName: "eth0",
		InputRules: []network.NFTInputRule{
			{Protocol: network.NFTProtoTCP, Ports: []int{22}, SourceCIDRs: []string{"203.0.113.0/24"}, Action: network.NFTActionDrop, Comment: "deny-office"},
			{Protocol: network.NFTProtoTCP, Ports: []int{22}, SourceCIDRs: []string{"203.0.113.7/32"}, Action: network.NFTActionAccept, Comment: "admin-host"},
		},
	}
	if _, ok := lockoutFinding(t, plan); !ok {
		t.Fatal("an accept whose every source an earlier drop covers is no way in")
	}
}

// The compiled shape the research probe found: a node override denying
// tcp/22 from anywhere and a fleet group allowing tcp/22 from the public zone.
// The plan rendered the drop first, dropped every new SSH connection, and the
// lint returned no findings.
func TestCompiledDenyAheadOfAPublicSSHAllowBlocks(t *testing.T) {
	plan, err := Compile(CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true, GroupIDs: []string{"g"},
			Overrides: []model.GuardRule{denyRule("deny-ssh", 22, model.NetEndpoint{Kind: model.NetRefAny})}},
		Groups:  []model.SecurityGroup{{ID: "g", Rules: []model.GuardRule{publicAllow("ssh", 22)}}},
		Zones:   ZoneMap([]model.GuardZone{{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}}}),
		Resolve: noNodes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lockoutFinding(t, plan); !ok {
		ruleset, _ := network.GenerateNFTPlan(plan)
		t.Fatalf("the compiled deny-then-allow plan must block:\n%s", ruleset)
	}
}

// Accept-only plans compile and lint exactly as they did: the converted
// legacy baseline shape, a public tcp/22 allow, still passes.
func TestCompiledAcceptOnlyPlanStillPasses(t *testing.T) {
	plan, err := Compile(CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "n1", Managed: true, GroupIDs: []string{"g"}},
		Groups:  []model.SecurityGroup{{ID: "g", Rules: []model.GuardRule{publicAllow("ssh", 22), publicAllow("web", 443)}}},
		Zones:   ZoneMap([]model.GuardZone{{ID: model.GuardZonePublic, Interfaces: []string{"eth0"}}}),
		Resolve: noNodes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.InputRules) != 0 || len(plan.PublicTCP) != 2 {
		t.Fatalf("an allow-only binding must keep the broad port list: %+v", plan)
	}
	if f, ok := lockoutFinding(t, plan); ok {
		t.Fatalf("an accept-only plan with tcp/22 must pass: %+v", f)
	}
}

func publicAllow(id string, port int) model.GuardRule {
	return model.GuardRule{
		ID: id, Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
		Ports:  []model.GuardPortRange{{From: port, To: port}},
		Remote: model.NetEndpoint{Kind: model.NetRefZone, ZoneID: model.GuardZonePublic},
	}
}

func denyRule(id string, port int, remote model.NetEndpoint) model.GuardRule {
	return model.GuardRule{
		ID: id, Action: model.NetRuleDeny, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP,
		Ports: []model.GuardPortRange{{From: port, To: port}}, Remote: remote,
	}
}
