package store

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestUpdateNodeMeta(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	beat := time.Now().UTC()
	allowlist := []string{"198.51.100.10/32"}
	if err := s.UpsertNode(model.Node{ID: "n1", Name: "old", Role: "edge", Tags: []string{"a"}, AgentSourceAllowlist: allowlist, Online: true, LastSeen: beat}); err != nil {
		t.Fatal(err)
	}

	n, ok, err := s.UpdateNodeMeta("n1", "new-name", "hub", "rack 9", []string{" y ", "x", "", "x"}, nil, nil)
	if err != nil || !ok {
		t.Fatalf("UpdateNodeMeta: ok=%v err=%v", ok, err)
	}
	if n.Name != "new-name" || n.Role != "hub" || n.Comment != "rack 9" {
		t.Fatalf("name/role not updated: %+v", n)
	}
	if len(n.Tags) != 2 || n.Tags[0] != "x" || n.Tags[1] != "y" {
		t.Fatalf("tags not trimmed/deduped/sorted: %+v", n.Tags)
	}
	if len(n.AgentSourceAllowlist) != 1 || n.AgentSourceAllowlist[0] != "198.51.100.10/32" {
		t.Fatalf("nil allowlist update should preserve policy: %+v", n.AgentSourceAllowlist)
	}

	// Liveness fields must be preserved (no read-modify-write clobber).
	got, ok := s.Node("n1")
	if !ok || !got.Online || !got.LastSeen.Equal(beat) {
		t.Fatalf("liveness clobbered: online=%v lastSeen=%v", got.Online, got.LastSeen)
	}
	cleared := []string{}
	n, ok, err = s.UpdateNodeMeta("n1", "new-name", "hub", "rack 9", []string{"x"}, &cleared, nil)
	if err != nil || !ok {
		t.Fatalf("clear allowlist: ok=%v err=%v", ok, err)
	}
	if len(n.AgentSourceAllowlist) != 0 {
		t.Fatalf("empty non-nil allowlist should clear policy: %+v", n.AgentSourceAllowlist)
	}

	// Inventory carries nil=unchanged, non-nil=replace (inner nil clears) semantics.
	purity := 98
	set := &model.NodeInventory{PurityPercent: &purity, Quality: "high", Notes: "residential"}
	n, ok, err = s.UpdateNodeMeta("n1", "new-name", "hub", "rack 9", []string{"x"}, nil, &set)
	if err != nil || !ok {
		t.Fatalf("set inventory: ok=%v err=%v", ok, err)
	}
	if n.Inventory == nil || n.Inventory.PurityPercent == nil || *n.Inventory.PurityPercent != 98 || n.Inventory.Quality != "high" {
		t.Fatalf("inventory not stored: %+v", n.Inventory)
	}
	// A nil outer pointer leaves the stored inventory untouched.
	n, ok, err = s.UpdateNodeMeta("n1", "new-name", "hub", "rack 9", []string{"x"}, nil, nil)
	if err != nil || !ok {
		t.Fatalf("inventory unchanged: ok=%v err=%v", ok, err)
	}
	if n.Inventory == nil || n.Inventory.Quality != "high" {
		t.Fatalf("nil inventory update should preserve stored value: %+v", n.Inventory)
	}
	// The returned copy must not alias the stored inventory pointer.
	if got, _ := s.Node("n1"); got.Inventory == n.Inventory {
		t.Fatal("UpdateNodeMeta must return a deep copy of inventory")
	}
	// A non-nil outer wrapping a nil inner clears the stored inventory.
	var clear *model.NodeInventory
	n, ok, err = s.UpdateNodeMeta("n1", "new-name", "hub", "rack 9", []string{"x"}, nil, &clear)
	if err != nil || !ok {
		t.Fatalf("clear inventory: ok=%v err=%v", ok, err)
	}
	if n.Inventory != nil {
		t.Fatalf("nil inner inventory should clear stored value: %+v", n.Inventory)
	}

	// Unknown node returns ok=false, no error.
	if _, ok, err := s.UpdateNodeMeta("nope", "x", "y", "", nil, nil, nil); ok || err != nil {
		t.Fatalf("unknown node: ok=%v err=%v", ok, err)
	}
}
