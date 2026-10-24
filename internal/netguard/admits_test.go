package netguard

import (
	"testing"

	"github.com/LatticeNet/lattice-server/internal/network"
)

func TestAdmitsJudgesScopeStrictlyAndDropsGenerously(t *testing.T) {
	base := network.NFTPlan{InterfaceName: "ens3", WireGuardCIDR: "10.66.0.0/24"}

	public := base
	public.PublicUDP = []int{53}
	if !Admits(public, network.NFTProtoUDP, 53, AudiencePublic) {
		t.Fatal("a public udp list admits the public")
	}
	if Admits(public, network.NFTProtoTCP, 53, AudiencePublic) || Admits(public, network.NFTProtoUDP, 53, AudienceMesh) {
		t.Fatal("a public udp list says nothing about tcp, or about the mesh source range")
	}

	mesh := base
	mesh.WireGuardTCP = []int{53}
	if !Admits(mesh, network.NFTProtoTCP, 53, AudienceMesh) || Admits(mesh, network.NFTProtoTCP, 53, AudiencePublic) {
		t.Fatal("a wireguard tcp list admits the mesh and only the mesh")
	}

	onePeer := base
	onePeer.InputRules = []network.NFTInputRule{{SourceCIDRs: []string{"203.0.113.7/32"}, Protocol: network.NFTProtoUDP, Ports: []int{53}, Action: network.NFTActionAccept, Comment: "one peer"}}
	if Admits(onePeer, network.NFTProtoUDP, 53, AudiencePublic) {
		t.Fatal("an accept for one peer does not open a port to the public")
	}

	// An operator deny for one network leaves the port open to everyone else;
	// a deny for everything shadows the accept.
	denyOne := public
	denyOne.InputRules = []network.NFTInputRule{{SourceCIDRs: []string{"192.0.2.0/24"}, Protocol: network.NFTProtoAny, Action: network.NFTActionDrop, Comment: "bad net"}}
	if !Admits(denyOne, network.NFTProtoUDP, 53, AudiencePublic) {
		t.Fatal("a deny for one network must not close the port to everyone")
	}
	denyAll := public
	denyAll.InputRules = []network.NFTInputRule{{Protocol: network.NFTProtoUDP, Ports: []int{53}, Action: network.NFTActionDrop, Comment: "no dns"}}
	if Admits(denyAll, network.NFTProtoUDP, 53, AudiencePublic) {
		t.Fatal("an earlier drop of every source shadows the accept")
	}
}
