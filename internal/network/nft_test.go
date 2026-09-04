package network

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestGenerateNFTPlanRendersIPv6InputRules(t *testing.T) {
	plan, err := GenerateNFTPlan(NFTPlan{
		InputRules: []NFTInputRule{{
			SourceCIDRs: []string{"2001:db8::2", "198.51.100.2"},
			Protocol:    NFTProtoUDP,
			Ports:       []int{51820},
			Action:      NFTActionAccept,
			Comment:     "dual stack peer",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ip saddr 198.51.100.2 udp dport { 51820 } accept comment "dual stack peer"`,
		`ip6 saddr 2001:db8::2 udp dport { 51820 } accept comment "dual stack peer"`,
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, plan)
		}
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

// The plan has to be accepted by every nftables the fleet runs. `destroy
// table` was added in nftables 1.0.7; sixteen of the fleet's nft-capable nodes
// run Debian 12's 1.0.6, where `nft -c 'destroy table inet X'` fails with
// "syntax error, unexpected table, expecting string" while
// `nft -c 'add table inet X; delete table inet X'` returns 0 (verified on two
// Debian 12 nodes, 2026-09-03). The renderer therefore opens with the add/delete
// pair, which every version parses and which replaces the table whether or
// not it already exists.
func TestGenerateNFTPlanReplacesTheTableWithoutDestroy(t *testing.T) {
	plan, err := GenerateNFTPlan(NFTPlan{PublicTCP: []int{22}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "destroy") {
		t.Fatalf("plan uses a command nftables 1.0.6 does not parse:\n%s", plan)
	}
	if !strings.HasPrefix(plan, "add table inet lattice_guard\ndelete table inet lattice_guard\ntable inet lattice_guard {\n") {
		t.Fatalf("plan must replace the table with the version-independent add/delete pair:\n%s", plan)
	}
}

// The same fact checked against a real nft binary when one is available. On a
// developer machine without nftables, or without the privilege `nft -c` needs
// to evaluate a ruleset, this skips rather than pretending it ran.
func TestGenerateNFTPlanPassesNFTCheck(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed; the rendered plan cannot be checked here")
	}
	if os.Geteuid() != 0 {
		t.Skip("nft -c needs root to evaluate a ruleset")
	}
	plan, err := GenerateNFTPlan(NFTPlan{PublicTCP: []int{22, 443}, PublicUDP: []int{53}, WireGuardTCP: []int{9100}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "guard.nft")
	if err := os.WriteFile(path, []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(nft, "-c", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the rendered plan: %v\n%s\n%s", err, out, plan)
	}
}
