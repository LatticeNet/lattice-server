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
