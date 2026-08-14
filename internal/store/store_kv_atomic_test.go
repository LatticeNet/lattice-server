package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestKVPreCommitPersistenceFailurePublishesNoLiveMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		seed   bool
		mutate func(*Store) error
		want   bool
	}{
		{name: "put", mutate: func(st *Store) error {
			return st.PutKV(model.KVEntry{Bucket: "plugin:p", Key: "record", Value: `{"new":true}`})
		}},
		{name: "delete", seed: true, mutate: func(st *Store) error { return st.DeleteKV("plugin:p", "record") }, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "state")
			path := filepath.Join(parent, "state.json")
			st, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.seed {
				if err := st.PutKV(model.KVEntry{Bucket: "plugin:p", Key: "record", Value: `{"old":true}`}); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.RemoveAll(parent); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(parent, []byte("blocks mkdir"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.mutate(st); err == nil {
				t.Fatal("expected pre-commit persistence failure")
			}
			_, got := st.KVEntry("plugin:p", "record")
			if got != tc.want {
				t.Fatalf("live KV publication=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestKVPostRenameDurabilityErrorPublishesCommittedMutation(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.syncParentDir = func(string) error { return errors.New("forced directory sync failure") }
	if err := st.PutKV(model.KVEntry{Bucket: "plugin:p", Key: "record", Value: `{"committed":true}`}); err == nil {
		t.Fatal("expected post-rename durability error")
	}
	if entry, ok := st.KVEntry("plugin:p", "record"); !ok || entry.Value != `{"committed":true}` {
		t.Fatalf("committed KV mutation was not published: ok=%v entry=%+v", ok, entry)
	}
}
