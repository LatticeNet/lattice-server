package store

import (
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// KV and Static used to be written in full to state.json on every state write,
// while their bbolt buckets were populated only by a whole-state import and the
// merge on open threw away what it read. These cover the move to the
// record-level path: nothing may be stranded, nothing may come back from the
// dead, and neither domain may appear in the JSON file again.

func TestKVAndStaticMigrateOutOfJSONState(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state-hot.db")
	c := testCipher(t)

	// Written under the old behaviour: no hot store, so both land in the JSON.
	s, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutKV(model.KVEntry{Bucket: "legacy", Key: "k", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutStatic(model.StaticObject{Bucket: "legacy", Path: "a.js", Content: "// old"}); err != nil {
		t.Fatal(err)
	}
	before, err := LoadJSONState(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := before.KV["legacy/k"]; !ok {
		t.Fatal("the fixture is wrong: the old behaviour must put KV in the JSON state")
	}
	if _, ok := before.Static["legacy/a.js"]; !ok {
		t.Fatal("the fixture is wrong: the old behaviour must put static in the JSON state")
	}

	// Opening the hot store is the upgrade. Entries that exist only in the JSON
	// have to cross, or they vanish the moment it stops being read.
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if entry, ok := s.KVEntry("legacy", "k"); !ok || entry.Value != "v" {
		t.Fatalf("KV was stranded by the migration: ok=%v entry=%+v", ok, entry)
	}
	if obj, ok := s.StaticObject("legacy", "a.js"); !ok || obj.Content != "// old" {
		t.Fatalf("static object was stranded by the migration: ok=%v obj=%+v", ok, obj)
	}

	// The next state write must leave both domains out of the file.
	if err := s.PutKV(model.KVEntry{Bucket: "after", Key: "k2", Value: "v2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "n1", Name: "forces a JSON write"}); err != nil {
		t.Fatal(err)
	}
	after, err := LoadJSONState(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.KV) != 0 {
		t.Fatalf("KV is still written to the JSON state: %+v", after.KV)
	}
	if len(after.Static) != 0 {
		t.Fatalf("static is still written to the JSON state: %+v", after.Static)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if entry, ok := reopened.KVEntry("legacy", "k"); !ok || entry.Value != "v" {
		t.Fatalf("migrated KV did not survive a reopen: ok=%v entry=%+v", ok, entry)
	}
	if entry, ok := reopened.KVEntry("after", "k2"); !ok || entry.Value != "v2" {
		t.Fatalf("KV written after the move did not survive a reopen: ok=%v entry=%+v", ok, entry)
	}
	if obj, ok := reopened.StaticObject("legacy", "a.js"); !ok || obj.Content != "// old" {
		t.Fatalf("migrated static object did not survive a reopen: ok=%v obj=%+v", ok, obj)
	}
}

// The merge takes bolt unconditionally rather than falling back to the JSON
// copy when bolt looks empty. Treating emptiness as "keep what the file says"
// would resurrect every entry ever deleted, which is the whole reason the
// fallback the other domains use is wrong here.
func TestDeletedKVAndStaticStayDeletedAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state-hot.db")
	c := testCipher(t)

	s, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutKV(model.KVEntry{Bucket: "b", Key: "gone", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutStatic(model.StaticObject{Bucket: "b", Path: "gone.js", Content: "// x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteKV("b", "gone"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteStatic("b", "gone.js"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if entry, ok := reopened.KVEntry("b", "gone"); ok {
		t.Fatalf("a deleted KV entry came back: %+v", entry)
	}
	if obj, ok := reopened.StaticObject("b", "gone.js"); ok {
		t.Fatalf("a deleted static object came back: %+v", obj)
	}
}

// Static was write-only. Without a delete, replacing a file's generator script
// would leave every previous version behind forever.
func TestStaticObjectsCanBeDeleted(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenWithCipher(filepath.Join(dir, "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutStatic(model.StaticObject{Bucket: "scripts", Path: "one.js", Content: "// a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutStatic(model.StaticObject{Bucket: "scripts", Path: "two.js", Content: "// b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteStatic("scripts", "one.js"); err != nil {
		t.Fatal(err)
	}
	remaining := s.Static("scripts")
	if len(remaining) != 1 || remaining[0].Path != "two.js" {
		t.Fatalf("delete removed the wrong objects: %+v", remaining)
	}
	// Deleting something that was never there is not an error: callers delete on
	// a path they cannot always know is populated.
	if err := s.DeleteStatic("scripts", "never.js"); err != nil {
		t.Fatalf("deleting a missing object failed: %v", err)
	}
}
