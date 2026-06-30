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
	if err := s.UpsertNode(model.Node{ID: "n1", Name: "old", Role: "edge", Tags: []string{"a"}, Online: true, LastSeen: beat}); err != nil {
		t.Fatal(err)
	}

	n, ok, err := s.UpdateNodeMeta("n1", "new-name", "hub", "rack 9", []string{" y ", "x", "", "x"})
	if err != nil || !ok {
		t.Fatalf("UpdateNodeMeta: ok=%v err=%v", ok, err)
	}
	if n.Name != "new-name" || n.Role != "hub" || n.Comment != "rack 9" {
		t.Fatalf("name/role not updated: %+v", n)
	}
	if len(n.Tags) != 2 || n.Tags[0] != "x" || n.Tags[1] != "y" {
		t.Fatalf("tags not trimmed/deduped/sorted: %+v", n.Tags)
	}

	// Liveness fields must be preserved (no read-modify-write clobber).
	got, ok := s.Node("n1")
	if !ok || !got.Online || !got.LastSeen.Equal(beat) {
		t.Fatalf("liveness clobbered: online=%v lastSeen=%v", got.Online, got.LastSeen)
	}

	// Unknown node returns ok=false, no error.
	if _, ok, err := s.UpdateNodeMeta("nope", "x", "y", "", nil); ok || err != nil {
		t.Fatalf("unknown node: ok=%v err=%v", ok, err)
	}
}
