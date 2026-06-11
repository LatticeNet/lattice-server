package network

import (
	"strings"
	"testing"
)

func TestGenerateNFTPlanRejectsBadCIDR(t *testing.T) {
	for _, bad := range []string{"not-a-cidr", "10.0.0.0", "}; evil", "2001:db8::/32"} {
		if _, err := GenerateNFTPlan(NFTPlan{WireGuardCIDR: bad}); err == nil {
			t.Fatalf("expected CIDR %q to be rejected", bad)
		}
	}
}

func TestGenerateNFTPlanRejectsBadInterface(t *testing.T) {
	for _, bad := range []string{"eth0; drop", "verylonginterfacename", "wg 0", `eth"`} {
		if _, err := GenerateNFTPlan(NFTPlan{InterfaceName: bad}); err == nil {
			t.Fatalf("expected interface %q to be rejected", bad)
		}
	}
}

func TestGenerateNFTPlanCanonicalizesAndUsesInterface(t *testing.T) {
	plan, err := GenerateNFTPlan(NFTPlan{
		InterfaceName: "eth0",
		WireGuardCIDR: "10.66.0.5/24", // non-canonical host bits
		PublicTCP:     []int{443, 80},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "10.66.0.0/24") {
		t.Fatalf("CIDR should be canonicalized to network address:\n%s", plan)
	}
	if !strings.Contains(plan, `iifname "eth0" tcp dport { 80, 443 }`) {
		t.Fatalf("public ports should be bound to the interface:\n%s", plan)
	}
	if !strings.Contains(plan, "policy drop") {
		t.Fatalf("ruleset must default-drop:\n%s", plan)
	}
}
