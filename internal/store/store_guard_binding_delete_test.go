package store

import (
	"errors"
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

// The managed check must run under the same lock as the delete. A caller that
// checked managed=false in one lock acquisition and deletes in another can be
// raced by an upsert that flips the binding to managed=true; the store itself
// is the last line of defence, so it refuses a managed binding regardless of
// what the caller believed when it decided to delete.
func TestDeleteNodeGuardBindingRefusesManaged(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(statePath, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", Managed: true, ZoneIDs: []string{"tailscale"}})
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := s.DeleteNodeGuardBinding("node-a")
	if !errors.Is(err, ErrGuardBindingManaged) {
		t.Fatalf("delete of a managed binding = ok %v, err %v; want ErrGuardBindingManaged", ok, err)
	}
	if !ok {
		t.Fatal("a refused delete must still report that the binding exists")
	}
	kept, ok := s.NodeGuardBinding("node-a")
	if !ok || !kept.Managed || kept.Version != saved.Version {
		t.Fatalf("managed binding must survive a refused delete, got %+v ok=%v", kept, ok)
	}

	// Unmanaging is the existing path; once managed=false the delete goes through.
	kept.Managed = false
	if _, err := s.UpsertNodeGuardBinding(kept); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.DeleteNodeGuardBinding("node-a"); err != nil || !ok {
		t.Fatalf("delete after unmanage = ok %v, err %v", ok, err)
	}
}
