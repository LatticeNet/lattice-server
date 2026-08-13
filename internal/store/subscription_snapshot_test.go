package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

const snapshotRawCanary = "vless://credential-canary@example.invalid:443"

func TestSubscriptionSnapshotRawEncryptedJSONRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cipher := testCipher(t)
	s, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	snap := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: snapshotRawCanary, FetchedAt: time.Now().UTC()}
	if err := s.UpsertSubscriptionSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), snapshotRawCanary) {
		t.Fatal("snapshot Raw leaked to JSON")
	}
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.SubscriptionSnapshot("p", "s")
	if !ok || got.Raw != snapshotRawCanary {
		t.Fatalf("round trip = %+v, %v", got, ok)
	}
}

func TestSnapshotOnlyAndShareOnlyLostKeyFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*Store) error
	}{
		{name: "snapshot", seed: func(s *Store) error {
			return s.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: snapshotRawCanary})
		}},
		{name: "share", seed: func(s *Store) error {
			return s.UpsertSubscriptionShare(model.SubscriptionShare{ID: "share", Token: "bearer-canary"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			s, err := OpenWithCipher(path, testCipher(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.seed(s); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenWithCipher(path, secret.Disabled()); err == nil {
				t.Fatal("encrypted record opened without its master key")
			}
		})
	}
}

func TestSubscriptionSnapshotRawEncryptedFullBoltRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	bs, err := OpenBoltState(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	state := emptyState()
	state.SubscriptionSnapshots["p/s"] = model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: snapshotRawCanary, FetchedAt: time.Now().UTC()}
	if err := bs.ImportState(state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), snapshotRawCanary) {
		t.Fatal("snapshot Raw leaked to Bolt")
	}
	got, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if got.SubscriptionSnapshots["p/s"].Raw != snapshotRawCanary {
		t.Fatalf("round trip = %+v", got.SubscriptionSnapshots["p/s"])
	}
}

func TestSubscriptionSnapshotRawEncryptedRuntimeHotAndDeleteAuthoritative(t *testing.T) {
	dir := t.TempDir()
	jsonPath, boltPath := filepath.Join(dir, "state.json"), filepath.Join(dir, "hot.db")
	cipher := testCipher(t)
	s, err := OpenWithCipher(jsonPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: snapshotRawCanary}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(boltPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), snapshotRawCanary) {
		t.Fatal("snapshot Raw leaked to runtime-hot Bolt")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(jsonPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if got, ok := reopened.SubscriptionSnapshot("p", "s"); !ok || got.Raw != snapshotRawCanary {
		t.Fatalf("hot reopen = %+v, %v", got, ok)
	}
	if err := reopened.DeleteSubscriptionSnapshot("p", "s"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := OpenWithCipher(jsonPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if _, ok := again.SubscriptionSnapshot("p", "s"); ok {
		t.Fatal("deleted hot snapshot resurrected")
	}
}

func TestSubscriptionSnapshotPersistenceFailurePreservesLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	base := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: "last-good"}
	if err := s.UpsertSubscriptionSnapshot(base); err != nil {
		t.Fatal(err)
	}
	originalPath := s.path
	s.path = filepath.Join(t.TempDir(), "existing-directory")
	if err := os.MkdirAll(s.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: "must-not-publish"}); err == nil {
		t.Fatal("persistence failure not surfaced")
	}
	s.path = originalPath
	got, _ := s.SubscriptionSnapshot("p", "s")
	if got.Raw != "last-good" {
		t.Fatalf("memory published failed write: %+v", got)
	}
	reopened, err := OpenWithCipher(path, s.cipher)
	if err != nil {
		t.Fatal(err)
	}
	disk, _ := reopened.SubscriptionSnapshot("p", "s")
	if disk.Raw != "last-good" {
		t.Fatalf("disk lost last good: %+v", disk)
	}
}

func TestSubscriptionSnapshotPostRenameDurabilityPublishesCommittedValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	s.syncParentDir = func(string) error { return errors.New("dir fsync failed") }
	err = s.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: "committed"})
	if err == nil {
		t.Fatal("durability degradation not surfaced")
	}
	got, ok := s.SubscriptionSnapshot("p", "s")
	if !ok || got.Raw != "committed" {
		t.Fatalf("committed rename was not published: %+v %v", got, ok)
	}
}
