package server

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func findDupGroup(groups []duplicateGroup, reason string) *duplicateGroup {
	for i := range groups {
		if groups[i].Reason == reason {
			return &groups[i]
		}
	}
	return nil
}

func TestDetectDuplicateNodes(t *testing.T) {
	facts := func(host, cpu string, mem uint64) model.HostFacts {
		return model.HostFacts{Hostname: host, CPUModel: cpu, CPUCores: 4, MemoryTotal: mem, Virtualization: "kvm"}
	}
	nodes := []model.Node{
		// wireguard_key duplicate pair
		{ID: "wg-a", WireGuardPublicKey: "PUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{ID: "wg-b", WireGuardPublicKey: "PUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		// same machine re-enrolled: same public AND internal IP
		{ID: "ip-a", PublicIP: "203.0.113.10", InternalIP: "192.168.1.5"},
		{ID: "ip-b", PublicIP: "203.0.113.10", InternalIP: "192.168.1.5"},
		// NAT siblings: same public IP, DIFFERENT internal IPs -> NOT a duplicate
		{ID: "nat-a", PublicIP: "203.0.113.99", InternalIP: "172.17.0.2"},
		{ID: "nat-b", PublicIP: "203.0.113.99", InternalIP: "172.17.0.3"},
		// host fingerprint duplicate pair
		{ID: "fp-a", HostFacts: facts("box1", "Xeon E5", 8192)},
		{ID: "fp-b", HostFacts: facts("box1", "Xeon E5", 8192)},
		// distinct VM (same hw, different hostname) -> NOT a fingerprint dup
		{ID: "vm-a", HostFacts: facts("alpha", "Xeon E5", 8192)},
		{ID: "vm-b", HostFacts: facts("beta", "Xeon E5", 8192)},
		// disabled duplicate -> excluded
		{ID: "off-a", WireGuardPublicKey: "DISABLEDKEYZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=", Disabled: true},
		{ID: "off-b", WireGuardPublicKey: "DISABLEDKEYZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=", Disabled: true},
		// lone node
		{ID: "solo", PublicIP: "198.51.100.1", InternalIP: "10.0.0.9"},
	}

	groups := detectDuplicateNodes(nodes)

	wg := findDupGroup(groups, "wireguard_key")
	if wg == nil || len(wg.NodeIDs) != 2 || wg.NodeIDs[0] != "wg-a" || wg.NodeIDs[1] != "wg-b" {
		t.Fatalf("wireguard_key group wrong: %+v", wg)
	}
	if wg.Confidence != "high" {
		t.Fatalf("wireguard confidence: %s", wg.Confidence)
	}

	ip := findDupGroup(groups, "public_internal_ip")
	if ip == nil || len(ip.NodeIDs) != 2 || ip.NodeIDs[0] != "ip-a" || ip.NodeIDs[1] != "ip-b" {
		t.Fatalf("public_internal_ip group wrong: %+v", ip)
	}

	fp := findDupGroup(groups, "host_fingerprint")
	if fp == nil || len(fp.NodeIDs) != 2 || fp.NodeIDs[0] != "fp-a" || fp.NodeIDs[1] != "fp-b" {
		t.Fatalf("host_fingerprint group wrong: %+v", fp)
	}
	if fp.Confidence != "medium" {
		t.Fatalf("fingerprint confidence: %s", fp.Confidence)
	}

	// NAT siblings, distinct-hostname VMs, disabled pair, and the solo node must
	// NOT appear in any group.
	for _, g := range groups {
		for _, id := range g.NodeIDs {
			switch id {
			case "nat-a", "nat-b", "vm-a", "vm-b", "off-a", "off-b", "solo":
				t.Fatalf("node %s should not be flagged as duplicate (group %+v)", id, g)
			}
		}
	}
}
