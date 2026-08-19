package store

import (
	"errors"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Once KV and Static moved onto the record-level path, bolt became the only
// durable copy: jsonPersistStateFrom drops both domains, so nothing else on
// disk carries them. That makes the write order load-bearing. If the in-memory
// map were updated first, a bolt write that failed would be reported as an
// error while the entry stayed readable through KVEntry and StaticObject until
// the next restart silently dropped it, which is the worst of both outcomes:
// the caller is told the write failed and the reader is told it succeeded.
//
// These pin the order by making bolt refuse writes. A read-only reopen is the
// only fault that reaches the bolt path, because bolt writes through an fd and
// an mmap that are established at open time, so the filesystem tricks used for
// the JSON path have no effect once the database is open.

func reopenHotStoreReadOnly(t *testing.T, s *Store, path string) {
	t.Helper()
	if err := s.runtimeBoltHot.db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s.runtimeBoltHot.db = db
}

func TestKVWriteFailureLeavesNothingReadable(t *testing.T) {
	dir := t.TempDir()
	boltPath := filepath.Join(dir, "state-hot.db")
	s, err := OpenWithCipher(filepath.Join(dir, "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if err := s.PutKV(model.KVEntry{Bucket: "b", Key: "survivor", Value: "kept"}); err != nil {
		t.Fatal(err)
	}

	reopenHotStoreReadOnly(t, s, boltPath)

	if err := s.PutKV(model.KVEntry{Bucket: "b", Key: "doomed", Value: "v"}); !errors.Is(err, bolterrors.ErrDatabaseReadOnly) {
		t.Fatalf("a write to a read-only hot store must fail: %v", err)
	}
	if entry, ok := s.KVEntry("b", "doomed"); ok {
		t.Fatalf("a failed write was left readable in memory: %+v", entry)
	}

	// The delete half of the same property: a deletion bolt refused must not
	// remove the entry from the readable copy either.
	if err := s.DeleteKV("b", "survivor"); !errors.Is(err, bolterrors.ErrDatabaseReadOnly) {
		t.Fatalf("a delete against a read-only hot store must fail: %v", err)
	}
	if _, ok := s.KVEntry("b", "survivor"); !ok {
		t.Fatal("a failed delete removed the entry from the readable copy")
	}
}

func TestStaticWriteFailureLeavesNothingReadable(t *testing.T) {
	dir := t.TempDir()
	boltPath := filepath.Join(dir, "state-hot.db")
	s, err := OpenWithCipher(filepath.Join(dir, "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if err := s.PutStatic(model.StaticObject{Bucket: "b", Path: "keep.js", Content: "// kept"}); err != nil {
		t.Fatal(err)
	}

	reopenHotStoreReadOnly(t, s, boltPath)

	if err := s.PutStatic(model.StaticObject{Bucket: "b", Path: "drop.js", Content: "// v"}); !errors.Is(err, bolterrors.ErrDatabaseReadOnly) {
		t.Fatalf("a write to a read-only hot store must fail: %v", err)
	}
	if obj, ok := s.StaticObject("b", "drop.js"); ok {
		t.Fatalf("a failed write was left readable in memory: %+v", obj)
	}

	if err := s.DeleteStatic("b", "keep.js"); !errors.Is(err, bolterrors.ErrDatabaseReadOnly) {
		t.Fatalf("a delete against a read-only hot store must fail: %v", err)
	}
	if _, ok := s.StaticObject("b", "keep.js"); !ok {
		t.Fatal("a failed delete removed the object from the readable copy")
	}
}
