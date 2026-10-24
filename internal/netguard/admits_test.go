package netguard

import (
	"testing"

	"github.com/LatticeNet/lattice-server/internal/network"
)

var (
	publicAudience = Audience{}
	meshAudience   = Audience{Mesh: true}
)

func TestAdmitsJudgesScopeStrictlyAndDropsGenerously(t *testing.T) {
	base := network.NFTPlan{InterfaceName: "ens3", WireGuardCIDR: "10.66.0.0/24"}

	public := base
	public.PublicUDP = []int{53}
	if !Admits(public, network.NFTProtoUDP, 53, publicAudience) {
		t.Fatal("a public udp list admits the public")
	}
	if Admits(public, network.NFTProtoTCP, 53, publicAudience) || Admits(public, network.NFTProtoUDP, 53, meshAudience) {
		t.Fatal("a public udp list says nothing about tcp, or about the mesh source range")
	}

	mesh := base
	mesh.WireGuardTCP = []int{53}
	if !Admits(mesh, network.NFTProtoTCP, 53, meshAudience) || Admits(mesh, network.NFTProtoTCP, 53, publicAudience) {
		t.Fatal("a wireguard tcp list admits the mesh and only the mesh")
	}

	onePeer := base
	onePeer.InputRules = []network.NFTInputRule{{SourceCIDRs: []string{"203.0.113.7/32"}, Protocol: network.NFTProtoUDP, Ports: []int{53}, Action: network.NFTActionAccept, Comment: "one peer"}}
	if Admits(onePeer, network.NFTProtoUDP, 53, publicAudience) {
		t.Fatal("an accept for one peer does not open a port to the public")
	}

	// An operator deny for one network leaves the port open to everyone else;
	// a deny for everything, however it is spelled, closes it.
	denyOne := public
	denyOne.InputRules = []network.NFTInputRule{{SourceCIDRs: []string{"192.0.2.0/24"}, Protocol: network.NFTProtoAny, Action: network.NFTActionDrop, Comment: "bad net"}}
	if !Admits(denyOne, network.NFTProtoUDP, 53, publicAudience) {
		t.Fatal("a deny for one network must not close the port to everyone")
	}
	for _, drop := range []network.NFTInputRule{
		{Protocol: network.NFTProtoUDP, Ports: []int{53}, Action: network.NFTActionDrop, Comment: "no dns"},
		{Interface: "ens3", Protocol: network.NFTProtoAny, Action: network.NFTActionDrop, Comment: "public drop"},
		{SourceCIDRs: []string{"0.0.0.0/0", "::/0"}, Protocol: network.NFTProtoAny, Action: network.NFTActionDrop, Comment: "drop all"},
	} {
		anyAccept := base
		anyAccept.InputRules = []network.NFTInputRule{drop, {Protocol: network.NFTProtoUDP, Ports: []int{53}, Action: network.NFTActionAccept, Comment: "dns"}}
		if Admits(anyAccept, network.NFTProtoUDP, 53, publicAudience) {
			t.Fatalf("an earlier %q drops every public source and closes the port", drop.Comment)
		}
	}

	// A drop on another interface leaves the public path open.
	otherIface := base
	otherIface.InputRules = []network.NFTInputRule{
		{Interface: "docker0", Protocol: network.NFTProtoAny, Action: network.NFTActionDrop, Comment: "docker"},
		{Protocol: network.NFTProtoUDP, Ports: []int{53}, Action: network.NFTActionAccept, Comment: "dns"},
	}
	if !Admits(otherIface, network.NFTProtoUDP, 53, publicAudience) {
		t.Fatal("a drop on another interface must not close the public path")
	}

	// A WireGuard zone defined by its interface admits the mesh through an
	// interface accept.
	trusted := base
	trusted.InputRules = []network.NFTInputRule{{Interface: "wg0", Protocol: network.NFTProtoAny, Action: network.NFTActionAccept, Comment: "trusted wireguard"}}
	if !Admits(trusted, network.NFTProtoUDP, 53, Audience{Mesh: true, MeshInterfaces: []string{"wg0"}}) {
		t.Fatal("a trusted wireguard interface admits the mesh")
	}
	if Admits(trusted, network.NFTProtoUDP, 53, meshAudience) {
		t.Fatal("without knowing the mesh interface, an interface accept is not assumed to be the mesh")
	}
}
