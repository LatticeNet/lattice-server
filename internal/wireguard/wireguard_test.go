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

// TestBuildMeshNormalizesAllowedIPsToHost guards C1: a node may report a mesh
// address carrying a wide prefix (or none), but every emitted peer AllowedIPs
// must be pinned to that node's single host route — never a wide range that
// would let the peer intercept/impersonate other nodes' traffic.
func TestBuildMeshNormalizesAllowedIPsToHost(t *testing.T) {
	cases := []struct {
		name        string
		reportedIP  string
		wantAllowed string
	}{
		{"ipv4 wide host prefix", "10.66.0.5/16", "10.66.0.5/32"},
		{"ipv4 network prefix", "10.66.0.0/16", "10.66.0.0/32"},
		{"ipv4 already host", "10.66.0.7/32", "10.66.0.7/32"},
		{"ipv4 bare", "10.66.0.9", "10.66.0.9/32"},
		{"ipv6 wide prefix", "fd66::5/48", "fd66::5/128"},
		{"ipv6 bare", "fd66::9", "fd66::9/128"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []model.Node{
				{ID: "self", Name: "hub", WireGuardIP: "10.66.0.1", WireGuardPublicKey: key(1)},
				{ID: "peer", Name: "p", WireGuardIP: tc.reportedIP, WireGuardPublicKey: key(2)},
			}
			_, peers, err := BuildMesh(nodes, nodes[0], 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(peers) != 1 {
				t.Fatalf("expected 1 peer, got %d: %+v", len(peers), peers)
			}
			if peers[0].AllowedIPs != tc.wantAllowed {
				t.Fatalf("AllowedIPs = %q, want %q (must be a single host route)", peers[0].AllowedIPs, tc.wantAllowed)
			}
			// Defense in depth: the result must always be a host route, never wide.
			if !strings.HasSuffix(peers[0].AllowedIPs, "/32") && !strings.HasSuffix(peers[0].AllowedIPs, "/128") {
				t.Fatalf("AllowedIPs %q is not a host route", peers[0].AllowedIPs)
			}
		})
	}
}

// TestBuildMeshSkipsUnparseableIP confirms a peer whose reported mesh address
// cannot be parsed is skipped rather than emitted with an unbounded route.
func TestBuildMeshSkipsUnparseableIP(t *testing.T) {
	nodes := []model.Node{
		{ID: "self", Name: "hub", WireGuardIP: "10.66.0.1", WireGuardPublicKey: key(1)},
		{ID: "bad", Name: "bad", WireGuardIP: "not-an-ip", WireGuardPublicKey: key(2)},
		{ID: "ok", Name: "ok", WireGuardIP: "10.66.0.3", WireGuardPublicKey: key(3)},
	}
	_, peers, err := BuildMesh(nodes, nodes[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].AllowedIPs != "10.66.0.3/32" {
		t.Fatalf("expected only the valid peer with a /32 route, got %+v", peers)
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
