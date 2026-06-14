package network

import (
	"strings"
	"testing"
)

func TestGenerateNFTPlan(t *testing.T) {
	plan, err := GenerateNFTPlan(NFTPlan{
		PublicTCP:    []int{443, 80},
		PublicUDP:    []int{53},
		WireGuardTCP: []int{22, 9100},
		WireGuardUDP: []int{51820},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"policy drop", "tcp dport { 80, 443 }", "udp dport { 53 }", "ip saddr @wg_peers4 tcp dport { 22, 9100 }"} {
		if !strings.Contains(plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, plan)
		}
	}
}

func TestNormalizeNFTPlanDefaultsAndDedupes(t *testing.T) {
	plan, err := NormalizeNFTPlan(NFTPlan{
		WireGuardCIDR: "10.66.0.9/24",
		PublicTCP:     []int{443, 80, 443},
		PublicUDP:     []int{53, 53},
		WireGuardTCP:  []int{9100, 22, 22},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.InterfaceName != "eth0" {
		t.Fatalf("default interface = %q", plan.InterfaceName)
	}
	if plan.WireGuardCIDR != "10.66.0.0/24" {
		t.Fatalf("canonical cidr = %q", plan.WireGuardCIDR)
	}
	if got := joinPorts(plan.PublicTCP); got != "80, 443" {
		t.Fatalf("public tcp = %q", got)
	}
	if got := joinPorts(plan.PublicUDP); got != "53" {
		t.Fatalf("public udp = %q", got)
	}
	if got := joinPorts(plan.WireGuardTCP); got != "22, 9100" {
		t.Fatalf("wg tcp = %q", got)
	}
}

func TestGenerateNFTPlanRejectsBadPort(t *testing.T) {
	if _, err := GenerateNFTPlan(NFTPlan{PublicTCP: []int{70000}}); err == nil {
		t.Fatal("expected invalid port rejection")
	}
}

func TestGenerateNFTPlanComposesInputRulesBeforeBroadAllows(t *testing.T) {
	plan, err := GenerateNFTPlan(NFTPlan{
		WireGuardTCP: []int{1234},
		InputRules: []NFTInputRule{{
			SourceCIDRs: []string{"198.51.100.2", "10.66.0.2/32", "10.66.0.2"},
			Protocol:    NFTProtoTCP,
			Ports:       []int{1234},
			Action:      NFTActionDrop,
			Comment:     `lattice rule deny-db "quoted"`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := `ip saddr { 10.66.0.2, 198.51.100.2 } tcp dport { 1234 } drop comment "lattice rule deny-db \"quoted\""`
	allow := `ip saddr @wg_peers4 tcp dport { 1234 } accept comment "wg tcp services"`
	if !strings.Contains(plan, deny) {
		t.Fatalf("plan missing composed deny:\n%s", plan)
	}
	if !strings.Contains(plan, allow) {
		t.Fatalf("plan missing broad allow:\n%s", plan)
	}
	if strings.Index(plan, deny) > strings.Index(plan, allow) {
		t.Fatalf("composed deny must render before broad allow:\n%s", plan)
	}
}

func TestGenerateNFTPlanRejectsBadInputRule(t *testing.T) {
	cases := []NFTInputRule{
		{SourceCIDRs: []string{"}; evil"}, Protocol: NFTProtoTCP, Action: NFTActionDrop},
		{Protocol: "icmp", Action: NFTActionDrop},
		{Protocol: NFTProtoTCP, Action: "reject"},
		{Protocol: NFTProtoAny, Ports: []int{22}, Action: NFTActionDrop},
	}
	for _, rule := range cases {
		if _, err := GenerateNFTPlan(NFTPlan{InputRules: []NFTInputRule{rule}}); err == nil {
			t.Fatalf("expected bad input rule to be rejected: %+v", rule)
		}
	}
}
