package store

import (
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A node's egress address is written when it moves and never because a pull
// saw it again; it survives a reopen, with the hot store's meta mirror too,
// and goes with the node.
func TestBeaconEgressIsDurableAndWrittenOnChange(t *testing.T) {
	dir := t.TempDir()
	open := func() *Store {
		t.Helper()
		s, err := OpenWithCipher(filepath.Join(dir, "state.json"), testCipher(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open()
	if err := s.UpsertNode(model.Node{ID: "n1", Name: "one"}); err != nil {
		t.Fatal(err)
	}
	set := func(addr string) int {
		t.Helper()
		before := s.testPersistCalls
		if err := s.SetBeaconEgress("n1", addr); err != nil {
			t.Fatal(err)
		}
		return s.testPersistCalls - before
	}
	if got := set("203.0.113.122"); got != 1 {
		t.Fatalf("the first address wrote %d times, want 1", got)
	}
	if got := set("203.0.113.122"); got != 0 {
		t.Fatalf("the same address again wrote %d times, want 0", got)
	}
	if got := set("203.0.113.123"); got != 1 {
		t.Fatalf("a moved address wrote %d times, want 1", got)
	}
	if err := s.SetBeaconEgress("ghost", "203.0.113.9"); err == nil {
		t.Fatal("an address was recorded for a node that does not exist")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open()
	if got := s.BeaconEgress("n1"); got != "203.0.113.123" {
		t.Fatalf("after a reopen the egress = %q", got)
	}
	if _, _, err := s.DeleteNode("n1"); err != nil {
		t.Fatal(err)
	}
	if got := s.BeaconEgress("n1"); got != "" {
		t.Fatalf("a deleted node kept its egress %q", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
