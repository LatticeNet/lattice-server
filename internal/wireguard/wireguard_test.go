package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// key returns a valid 44-char base64 WireGuard key seeded by b.
func key(b byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = b
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestBuildMeshSkipsSelfAndKeyless(t *testing.T) {
	nodes := []model.Node{
		{ID: "n1", Name: "hub", WireGuardIP: "10.66.0.1", WireGuardPublicKey: key(1)},
		{ID: "n2", Name: "tokyo", WireGuardIP: "10.66.0.2", WireGuardPublicKey: key(2), WireGuardEndpoint: "1.2.3.4:51820"},
		{ID: "n3", Name: "nat", WireGuardIP: "10.66.0.3", WireGuardPublicKey: key(3)},
		{ID: "n4", Name: "nokey", WireGuardIP: "10.66.0.4"},
	}
	iface, peers, err := BuildMesh(nodes, nodes[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if iface.Address != "10.66.0.1/24" || iface.ListenPort != 51820 {
		t.Fatalf("unexpected interface: %+v", iface)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers (self + keyless skipped), got %d", len(peers))
	}
	for _, p := range peers {
		if !strings.HasSuffix(p.AllowedIPs, "/32") {
			t.Fatalf("allowed ips must be /32, got %q", p.AllowedIPs)
		}
		if p.Keepalive != 25 {
			t.Fatalf("expected keepalive 25, got %d", p.Keepalive)
		}
	}
}

func TestGenerateConfigStructure(t *testing.T) {
	iface := Interface{Name: "wg0", Address: "10.66.0.1/24", ListenPort: 51820}
	peers := []Peer{
		{Name: "tokyo", PublicKey: key(2), AllowedIPs: "10.66.0.2/32", Endpoint: "1.2.3.4:51820", Keepalive: 25},
		{Name: "nat", PublicKey: key(3), AllowedIPs: "10.66.0.3/32", Keepalive: 25},
	}
	cfg, err := GenerateConfig(iface, peers)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[Interface]", "Address = 10.66.0.1/24", "ListenPort = 51820",
		"PrivateKey = " + PrivateKeyPlaceholder,
		"[Peer]", "AllowedIPs = 10.66.0.2/32", "Endpoint = 1.2.3.4:51820", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}
	// NAT peer must have no Endpoint line.
	if strings.Count(cfg, "Endpoint =") != 1 {
		t.Fatalf("expected exactly one Endpoint line:\n%s", cfg)
	}
}

func TestGenerateConfigRejectsBadInput(t *testing.T) {
	iface := Interface{Address: "10.66.0.1/24", ListenPort: 51820}
	// bad key
	if _, err := GenerateConfig(iface, []Peer{{PublicKey: "not-a-key", AllowedIPs: "10.0.0.2/32"}}); err == nil {
		t.Fatal("expected bad public key rejection")
	}
	// bad endpoint (injection attempt)
	if _, err := GenerateConfig(iface, []Peer{{PublicKey: key(2), AllowedIPs: "10.0.0.2/32", Endpoint: "evil\nPublicKey = x"}}); err == nil {
		t.Fatal("expected bad endpoint rejection")
	}
	// bad interface address
	if _, err := GenerateConfig(Interface{Address: "notcidr", ListenPort: 1}, nil); err == nil {
		t.Fatal("expected bad interface address rejection")
	}
}
