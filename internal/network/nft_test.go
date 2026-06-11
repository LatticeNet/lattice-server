package network

import (
	"strings"
	"testing"
)

func TestGenerateNFTPlan(t *testing.T) {
	plan, err := GenerateNFTPlan(NFTPlan{
		PublicTCP:    []int{443, 80},
		WireGuardTCP: []int{22, 9100},
		WireGuardUDP: []int{51820},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"policy drop", "tcp dport { 80, 443 }", "ip saddr @wg_peers4 tcp dport { 22, 9100 }"} {
		if !strings.Contains(plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, plan)
		}
	}
}

func TestGenerateNFTPlanRejectsBadPort(t *testing.T) {
	if _, err := GenerateNFTPlan(NFTPlan{PublicTCP: []int{70000}}); err == nil {
		t.Fatal("expected invalid port rejection")
	}
}
