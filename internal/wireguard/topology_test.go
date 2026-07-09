package wireguard

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func fleet() []model.Node {
	return []model.Node{
		{ID: "a", Name: "node-a", WireGuardIP: "10.66.0.1", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", WireGuardEndpoint: "203.0.113.1:51820", WireGuardPort: 51820},
		{ID: "b", Name: "node-b", WireGuardIP: "10.66.0.2", WireGuardPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="},
		{ID: "c", Name: "node-c", WireGuardIP: "10.66.0.3", WireGuardPublicKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", WireGuardEndpoint: "198.51.100.3:51820"},
		{ID: "keyless", Name: "no-key", WireGuardIP: "10.66.0.9"},
	}
}

// THE MIGRATION GATE (design-13 W1): the existing implicit fleet mesh, once
// expressed as a named network + memberships, must render exactly what
// BuildMesh renders today. A silent topology change is a silent loss of
// connectivity.
func TestMeshTopologyMatchesBuildMesh(t *testing.T) {
	nodes := fleet()
	for _, target := range nodes {
		if target.WireGuardIP == "" {
			continue
		}
		t.Run(target.ID, func(t *testing.T) {
			wantIface, wantPeers, wantErr := BuildMesh(nodes, target, 0)
			network, members := MeshFromNodes(nodes, 0)
			gotIface, gotPeers, gotErr := BuildTopology(network, members, nodes, target.ID)

			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("err mismatch: BuildMesh=%v BuildTopology=%v", wantErr, gotErr)
			}
			if wantErr != nil {
				return
			}
			// BuildTopology carries new optional fields; compare the fields
			// BuildMesh actually produces.
			if gotIface.Name != wantIface.Name || gotIface.Address != wantIface.Address ||
				gotIface.ListenPort != wantIface.ListenPort {
				t.Fatalf("interface mismatch:\n got %+v\nwant %+v", gotIface, wantIface)
			}
			if gotIface.MTU != 0 || len(gotIface.DNS) != 0 {
				t.Fatalf("mesh conversion must not invent MTU/DNS: %+v", gotIface)
			}
			if !reflect.DeepEqual(gotPeers, wantPeers) {
				t.Fatalf("peer mismatch:\n got %+v\nwant %+v", gotPeers, wantPeers)
			}

			// And the rendered configs must be identical, not merely equivalent.
			wantConf, err := GenerateConfig(wantIface, wantPeers)
			if err != nil {
				t.Fatal(err)
			}
			gotConf, err := GenerateConfig(gotIface, gotPeers)
			if err != nil {
				t.Fatal(err)
			}
			if gotConf != wantConf {
				t.Fatalf("rendered config diverged.\n--- BuildMesh ---\n%s\n--- BuildTopology ---\n%s", wantConf, gotConf)
			}
		})
	}
}

func TestHubAndSpokeEdges(t *testing.T) {
	nodes := fleet()
	network := model.WGNetwork{ID: "n", Topology: model.WGTopologyHubSpoke, ListenPort: 51820}
	members := []model.WGMembership{
		{NetworkID: "n", NodeID: "a", Address: "10.66.0.1", Role: model.WGRoleHub, Endpoint: "203.0.113.1:51820", ExtraAllowedIPs: []string{"192.168.50.0/24"}},
		{NetworkID: "n", NodeID: "b", Address: "10.66.0.2", Role: model.WGRoleSpoke},
		{NetworkID: "n", NodeID: "c", Address: "10.66.0.3", Role: model.WGRoleSpoke},
	}

	// A spoke peers only with the hub, and inherits the hub's advertised route.
	_, spokePeers, err := BuildTopology(network, members, nodes, "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(spokePeers) != 1 {
		t.Fatalf("spoke must peer only with the hub, got %d peers: %+v", len(spokePeers), spokePeers)
	}
	if spokePeers[0].AllowedIPs != "10.66.0.1/32, 192.168.50.0/24" {
		t.Fatalf("spoke must inherit the hub's reviewed routes, got %q", spokePeers[0].AllowedIPs)
	}
	if spokePeers[0].Endpoint != "203.0.113.1:51820" {
		t.Fatalf("spoke must dial the hub endpoint, got %q", spokePeers[0].Endpoint)
	}

	// The hub peers with every spoke, each pinned to its own host route.
	_, hubPeers, err := BuildTopology(network, members, nodes, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(hubPeers) != 2 {
		t.Fatalf("hub must peer with both spokes, got %d", len(hubPeers))
	}
	for _, p := range hubPeers {
		if !strings.HasSuffix(p.AllowedIPs, "/32") {
			t.Fatalf("spoke route must stay pinned to a host route, got %q", p.AllowedIPs)
		}
	}

	// Spoke-to-spoke edges must not exist.
	for _, p := range spokePeers {
		if p.Name == "node-c" {
			t.Fatal("spokes must not peer with each other in hub-and-spoke")
		}
	}
}

// A spoke advertising extra routes must never have them honored: only a hub's
// reviewed ExtraAllowedIPs widen a peer's AllowedIPs.
func TestSpokeCannotAdvertiseExtraRoutes(t *testing.T) {
	nodes := fleet()
	network := model.WGNetwork{ID: "n", Topology: model.WGTopologyHubSpoke, ListenPort: 51820}
	members := []model.WGMembership{
		{NetworkID: "n", NodeID: "a", Address: "10.66.0.1", Role: model.WGRoleHub},
		{NetworkID: "n", NodeID: "b", Address: "10.66.0.2", Role: model.WGRoleSpoke, ExtraAllowedIPs: []string{"0.0.0.0/0"}},
	}
	_, hubPeers, err := BuildTopology(network, members, nodes, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(hubPeers) != 1 || hubPeers[0].AllowedIPs != "10.66.0.2/32" {
		t.Fatalf("a spoke's self-declared routes must be ignored, got %+v", hubPeers)
	}
}

// A member reporting a wide prefix still gets pinned to a host route — the
// BuildMesh invariant, preserved.
func TestTopologyPinsWidePrefixToHostRoute(t *testing.T) {
	nodes := []model.Node{
		{ID: "a", WireGuardIP: "10.66.0.1", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{ID: "evil", Name: "evil", WireGuardIP: "10.66.0.5/16", WireGuardPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="},
	}
	network, members := MeshFromNodes(nodes, 0)
	_, peers, err := BuildTopology(network, members, nodes, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].AllowedIPs != "10.66.0.5/32" {
		t.Fatalf("a wide self-reported prefix must be pinned to /32, got %+v", peers)
	}
}

func TestCustomTopologyFailsClosed(t *testing.T) {
	nodes := fleet()
	network := model.WGNetwork{ID: "n", Topology: model.WGTopologyCustom, ListenPort: 51820}
	members := []model.WGMembership{
		{NetworkID: "n", NodeID: "a", Address: "10.66.0.1"},
		{NetworkID: "n", NodeID: "b", Address: "10.66.0.2"},
	}
	if _, _, err := BuildTopology(network, members, nodes, "a"); !errors.Is(err, ErrCustomTopology) {
		t.Fatalf("err = %v, want ErrCustomTopology (never silently degrade to mesh)", err)
	}
}

func TestTopologyRejectsUnknownModeAndNonMember(t *testing.T) {
	nodes := fleet()
	members := []model.WGMembership{{NetworkID: "n", NodeID: "a", Address: "10.66.0.1"}}

	if _, _, err := BuildTopology(model.WGNetwork{ID: "n", Topology: "star", ListenPort: 51820}, append(members,
		model.WGMembership{NetworkID: "n", NodeID: "b", Address: "10.66.0.2"}), nodes, "a"); err == nil {
		t.Fatal("unknown topology must fail closed")
	}
	if _, _, err := BuildTopology(model.WGNetwork{ID: "n", Topology: model.WGTopologyMesh}, members, nodes, "zzz"); err == nil {
		t.Fatal("a non-member target must be rejected")
	}
}

func TestGenerateConfigRendersMTUAndDNSOnlyWhenSet(t *testing.T) {
	iface := Interface{Name: "wg0", Address: "10.66.0.1/24", ListenPort: 51820}
	plain, err := GenerateConfig(iface, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "MTU") || strings.Contains(plain, "DNS") {
		t.Fatalf("unset MTU/DNS must not render:\n%s", plain)
	}

	iface.MTU = 1420
	iface.DNS = []string{"10.66.0.1", "1.1.1.1"}
	rich, err := GenerateConfig(iface, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rich, "MTU = 1420\n") || !strings.Contains(rich, "DNS = 10.66.0.1, 1.1.1.1\n") {
		t.Fatalf("MTU/DNS not rendered:\n%s", rich)
	}

	iface.MTU = 70000
	if _, err := GenerateConfig(iface, nil); err == nil {
		t.Fatal("absurd MTU must be rejected")
	}
	iface.MTU = 1420
	iface.DNS = []string{"not-an-ip"}
	if _, err := GenerateConfig(iface, nil); err == nil {
		t.Fatal("non-IP DNS must be rejected, never interpolated")
	}
}

func TestGenerateConfigValidatesMultiValueAllowedIPs(t *testing.T) {
	iface := Interface{Name: "wg0", Address: "10.66.0.1/24", ListenPort: 51820}
	good := []Peer{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: "10.66.0.2/32, 192.168.1.0/24"}}
	if _, err := GenerateConfig(iface, good); err != nil {
		t.Fatalf("multi-value AllowedIPs must be accepted: %v", err)
	}
	bad := []Peer{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: "10.66.0.2/32, not-a-cidr"}}
	if _, err := GenerateConfig(iface, bad); err == nil {
		t.Fatal("a malformed element must reject the whole value")
	}
}
