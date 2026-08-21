package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

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

// The name signal exists because it is the only one that survives a rebuild.
// A machine reinstalled and re-enrolled under a new record changes its
// hostname, its address, its agent identity and often its hardware
// fingerprint at once, so every other signal in this file stays silent.
func TestDuplicateDetectionCatchesARebuiltMachineByName(t *testing.T) {
	rebuilt := []model.Node{
		{
			ID: "node_old", Name: "[cd]-xuezhang-ca-NAT", PublicIP: "70.51.247.242",
			LastSeen:  time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC),
			HostFacts: model.HostFacts{Hostname: "xz-ca", CPUModel: "old", CPUCores: 2, MemoryTotal: 1 << 30},
		},
		{
			ID: "xz-ca", Name: "[cd]-xuezhang-ca-NAT", PublicIP: "142.188.146.51", Online: true,
			LastSeen:  time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
			HostFacts: model.HostFacts{Hostname: "ca.xuezhang.roobli.org", CPUModel: "new", CPUCores: 4, MemoryTotal: 425 << 20},
		},
	}
	groups := detectDuplicateNodes(rebuilt)
	var named *duplicateGroup
	for i := range groups {
		if groups[i].Reason == "name" {
			named = &groups[i]
		}
		if groups[i].Reason != "name" {
			t.Fatalf("a rebuilt machine shares nothing but its name; %s must not fire: %+v", groups[i].Reason, groups[i])
		}
	}
	if named == nil {
		t.Fatal("the name collision must be reported; it is the only surviving signal")
	}
	if named.Confidence != "certain" {
		t.Fatalf("a name is operator-assigned and unique by intent, so a collision cannot be a false positive; got %q", named.Confidence)
	}
	if len(named.NodeIDs) != 2 {
		t.Fatalf("both records belong to the group: %+v", named.NodeIDs)
	}
}

// A disabled node still holds its name, and reusing a retired node's name is
// exactly when a warning helps most, so the retirement skip must not apply to
// the name signal.
func TestNameCollisionIsReportedEvenForARetiredNode(t *testing.T) {
	groups := detectDuplicateNodes([]model.Node{
		{ID: "a", Name: "edge-1", Disabled: true},
		{ID: "b", Name: "edge-1"},
	})
	if len(groups) != 1 || groups[0].Reason != "name" {
		t.Fatalf("expected exactly one name group, got %+v", groups)
	}
}

func TestDistinctNamesAreNotACollision(t *testing.T) {
	groups := detectDuplicateNodes([]model.Node{
		{ID: "a", Name: "edge-1"},
		{ID: "b", Name: "edge-2"},
	})
	for _, g := range groups {
		if g.Reason == "name" {
			t.Fatalf("distinct names must not collide: %+v", g)
		}
	}
}

// The refusal is the half that actually prevents the mistake. Detection tells
// you afterwards; this stops the second record from existing.
func TestEnrollRefusesANameThatIsAlreadyTaken(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node_old", Name: "[cd]-xuezhang-ca-NAT"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	body := `{"name":"[cd]-xuezhang-ca-NAT","tags":["cd"]}`

	resp := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token", body, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("a taken name must be refused, got %d", resp.StatusCode)
	}
	var out struct {
		Conflict struct {
			ExistingNodeID string `json:"existing_node_id"`
			Remedy         string `json:"remedy"`
		} `json:"conflict"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Conflict.ExistingNodeID != "node_old" {
		t.Fatalf("the refusal must name the record it collided with, got %q", out.Conflict.ExistingNodeID)
	}
	// The refusal has to teach, because the correct action existed the whole
	// time and nothing pointed at it.
	if !strings.Contains(out.Conflict.Remedy, "rotate-token") {
		t.Fatalf("the refusal must point at the action the operator actually wanted: %q", out.Conflict.Remedy)
	}
	if before := len(st.Nodes()); before != 1 {
		t.Fatalf("a refused enrollment must create nothing, fleet is now %d", before)
	}

	// A speed bump, not a wall: two machines may legitimately share a name if
	// the operator says so, and the override is recorded.
	forced := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"name":"[cd]-xuezhang-ca-NAT","allow_duplicate_name":true}`, cookies, csrf)
	defer forced.Body.Close()
	if forced.StatusCode != http.StatusOK {
		t.Fatalf("an explicit override must be allowed, got %d", forced.StatusCode)
	}
	if after := len(st.Nodes()); after != 2 {
		t.Fatalf("the override must actually enroll, fleet is %d", after)
	}
}

// Re-enrolling by an existing id is a deliberate replace and keeps working;
// the name guard must not turn it into a self-collision.
func TestEnrollByExistingIDIsNotBlockedByItsOwnName(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "edge-1", Name: "edge-1"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	resp := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"edge-1","name":"edge-1"}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-enrolling the same record must not collide with itself, got %d", resp.StatusCode)
	}
}
