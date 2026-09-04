package store

import (
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestDeleteNodeGuardBindingRemovesAndPersists(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(statePath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteNodeGuardBinding("node-a"); err != nil {
		t.Fatalf("delete of a missing binding must not error: %v", err)
	} else if _, ok, _ := s.DeleteNodeGuardBinding("node-a"); ok {
		t.Fatal("delete of a missing binding must report ok=false")
	}

	saved, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", ZoneIDs: []string{"tailscale"}})
	if err != nil {
		t.Fatal(err)
	}
	deleted, ok, err := s.DeleteNodeGuardBinding("node-a")
	if err != nil || !ok {
		t.Fatalf("delete = ok %v, err %v", ok, err)
	}
	if deleted.NodeID != saved.NodeID || deleted.Version != saved.Version || len(deleted.ZoneIDs) != 1 || deleted.ZoneIDs[0] != "tailscale" {
		t.Fatalf("delete must return the removed record, got %+v want %+v", deleted, saved)
	}
	if _, ok := s.NodeGuardBinding("node-a"); ok {
		t.Fatal("binding still readable after delete")
	}

	// Persisted like its siblings: a fresh open from disk must not resurrect it.
	reopened, err := OpenWithCipher(statePath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.NodeGuardBinding("node-a"); ok {
		t.Fatal("deleted binding came back after reopening the store")
	}
}
