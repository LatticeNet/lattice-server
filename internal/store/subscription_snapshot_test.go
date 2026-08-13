package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	bolt "go.etcd.io/bbolt"
)

const snapshotRawCanary = "vless://credential-canary@example.invalid:443"

type legacySubscriptionSnapshotV1 struct {
	SchemaVersion  int       `json:"schema_version"`
	PluginID       string    `json:"plugin_id"`
	SubscriptionID string    `json:"subscription_id"`
	Raw            string    `json:"raw"`
	FetchedAt      time.Time `json:"fetched_at"`
}

func legacySubscriptionStateJSON(t *testing.T, rawValue string, shares map[string]model.SubscriptionShare) []byte {
	t.Helper()
	raw, err := json.Marshal(emptyState())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["subscription_snapshots"], err = json.Marshal(map[string]legacySubscriptionSnapshotV1{
		"p/s": {SchemaVersion: 1, PluginID: "p", SubscriptionID: "s", Raw: rawValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	fields["subscription_shares"], err = json.Marshal(shares)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testSubscriptionSnapshotV2(t *testing.T) model.SubscriptionSnapshot {
	t.Helper()
	root := "11111111-1111-4111-8111-111111111111"
	manifest, version, err := model.CanonicalSubscriptionSourceManifest(model.SubscriptionSourceManifestV1{
		Schema: model.SubscriptionSourceManifestSchemaV1, Renderer: model.SubscriptionSourceRendererV1,
		Identity:   model.SubscriptionSourceManifestIdentity{ID: "vpn-user", Generation: 3},
		EntryRoots: []string{root},
		Entries: []model.SubscriptionSourceManifestEntry{{
			Root: root,
			Endpoint: model.SubscriptionSourceManifestEndpoint{
				LineUUID: root, NodeID: "node-a", Label: "entry", Host: "entry.example.com", Port: 443,
				SNI: "entry.example.com", Fingerprint: "chrome", ALPN: []string{}, PublicKey: strings.Repeat("A", 43),
				ShortID: "0123456789abcdef", Flow: "xtls-rprx-vision",
			},
			Path: []model.SubscriptionSourceManifestEdge{},
			Terminal: model.SubscriptionSourceManifestTerminal{
				LineUUID: root, Generation: 4, ObservationRevision: 5, Status: "converged",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return model.SubscriptionSnapshot{
		SchemaVersion: model.SubscriptionSnapshotSchemaVersion, PluginID: "p", SubscriptionID: "s",
		Raw: snapshotRawCanary, SourceVersion: version, SourceManifest: manifest,
	}
}

func TestSubscriptionSnapshotIngressAndGettersValidateAndDeepCloneManifest(t *testing.T) {
	s, err := OpenWithCipher(filepath.Join(t.TempDir(), "state.json"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSubscriptionSnapshotV2(t)
	if err := s.UpsertSubscriptionSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.SourceManifest[0] = 'x'
	got, ok := s.SubscriptionSnapshot("p", "s")
	if !ok || got.SourceManifest[0] == 'x' {
		t.Fatal("snapshot ingress aliased caller manifest")
	}
	got.SourceManifest[0] = 'x'
	again, _ := s.SubscriptionSnapshot("p", "s")
	if again.SourceManifest[0] == 'x' {
		t.Fatal("snapshot getter aliased stored manifest")
	}
	listed := s.SubscriptionSnapshots()
	listed[0].SourceManifest[0] = 'x'
	again, _ = s.SubscriptionSnapshot("p", "s")
	if again.SourceManifest[0] == 'x' {
		t.Fatal("snapshot list aliased stored manifest")
	}

	invalid := testSubscriptionSnapshotV2(t)
	invalid.SourceManifest = append(invalid.SourceManifest, []byte(` {}`)...)
	if err := s.UpsertSubscriptionSnapshot(invalid); err == nil {
		t.Fatal("invalid source manifest accepted at ingress")
	}
	oversized := testSubscriptionSnapshotV2(t)
	oversized.Raw = strings.Repeat("r", model.MaxSubscriptionRawBytes+1)
	if err := s.UpsertSubscriptionSnapshot(oversized); err == nil {
		t.Fatal("oversized plaintext snapshot accepted at ingress")
	}
}

func TestEncryptedV1SubscriptionSnapshotRewritesAndReopensWithEmptyProvenance(t *testing.T) {
	dir := t.TempDir()
	cipher := testCipher(t)
	legacyEnvelope, err := cipher.Encrypt(snapshotRawCanary)
	if err != nil {
		t.Fatal(err)
	}
	legacySnapshot := legacySubscriptionSnapshotV1{SchemaVersion: 1, PluginID: "p", SubscriptionID: "s", Raw: legacyEnvelope}

	t.Run("json", func(t *testing.T) {
		path := filepath.Join(dir, "state.json")
		raw := legacySubscriptionStateJSON(t, legacyEnvelope, nil)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := OpenWithCipher(path, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(after, []byte(legacyEnvelope)) || bytes.Contains(after, []byte(snapshotRawCanary)) {
			t.Fatal("JSON rewrite retained the legacy envelope or plaintext")
		}
		reopened, err := OpenWithCipher(path, cipher)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := reopened.SubscriptionSnapshot("p", "s")
		if !ok || got.Raw != snapshotRawCanary || got.PersistedSchemaVersion() != 2 || got.NeedsRewrite() || got.SourceVersion != "" || len(got.SourceManifest) != 0 {
			t.Fatalf("rewritten JSON snapshot = %+v ok=%v", got, ok)
		}
	})

	t.Run("full bolt", func(t *testing.T) {
		path := filepath.Join(dir, "state.db")
		bs, err := OpenBoltState(path, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if err := bs.db.Update(func(tx *bolt.Tx) error {
			return putRecord(tx, boltBucketSubSnapshots, "p/s", legacySnapshot)
		}); err != nil {
			t.Fatal(err)
		}
		if err := bs.Close(); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		migrated, err := OpenBoltState(path, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if err := migrated.Close(); err != nil {
			t.Fatal(err)
		}
		afterInfo, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(before, afterInfo) {
			t.Fatal("encrypted v1 Bolt migration did not use a fresh replacement")
		}
		wholeFile, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wholeFile, []byte(legacyEnvelope)) || bytes.Contains(wholeFile, []byte(snapshotRawCanary)) {
			t.Fatal("fresh Bolt rewrite retained legacy envelope or plaintext")
		}
		reopened, err := OpenBoltState(path, cipher)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		state, err := reopened.ExportState()
		if err != nil {
			t.Fatal(err)
		}
		got := state.SubscriptionSnapshots["p/s"]
		if got.Raw != snapshotRawCanary || got.PersistedSchemaVersion() != 2 || got.NeedsRewrite() || got.SourceVersion != "" || len(got.SourceManifest) != 0 {
			t.Fatalf("rewritten Bolt snapshot = %+v", got)
		}
	})
}

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

func TestLegacyPlaintextSubscriptionSecretsMigrateInOneStagedRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	raw := legacySubscriptionStateJSON(t, snapshotRawCanary, map[string]model.SubscriptionShare{"share": {ID: "share", Token: "share-plaintext-canary"}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.testPersistCalls != 1 {
		t.Fatalf("migration persist calls = %d, want 1", s.testPersistCalls)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), snapshotRawCanary) || strings.Contains(string(after), "share-plaintext-canary") {
		t.Fatal("legacy plaintext survived migration")
	}
	if got, _ := s.SubscriptionSnapshot("p", "s"); got.Raw != snapshotRawCanary {
		t.Fatalf("snapshot changed: %+v", got)
	}
	if got, _ := s.SubscriptionShare("share"); got.Token != "share-plaintext-canary" {
		t.Fatalf("share changed: %+v", got)
	}
}

func TestCorruptSubscriptionEnvelopeMakesNoMigrationWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	firstCipher := testCipher(t)
	corruptEnvelope, err := firstCipher.Encrypt(snapshotRawCanary)
	if err != nil {
		t.Fatal(err)
	}
	raw := legacySubscriptionStateJSON(t, corruptEnvelope, nil)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	if _, err := OpenWithCipher(path, testCipher(t)); err == nil {
		t.Fatal("corrupt envelope accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(after); got != want {
		t.Fatalf("failed migration changed file digest: %x != %x", got, want)
	}
}

func TestMalformedSubscriptionEnvelopeMakesNoJSONOrBoltWrite(t *testing.T) {
	for _, malformed := range []string{"lat$", "lat$not-base64", "lat$YWJj"} {
		t.Run(malformed, func(t *testing.T) {
			jsonPath := filepath.Join(t.TempDir(), "state.json")
			raw := legacySubscriptionStateJSON(t, malformed, nil)
			if err := os.WriteFile(jsonPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			wantJSON := sha256.Sum256(raw)
			if _, err := OpenWithCipher(jsonPath, testCipher(t)); err == nil {
				t.Fatal("malformed JSON envelope accepted")
			}
			afterJSON, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256.Sum256(afterJSON); got != wantJSON {
				t.Fatalf("failed JSON open changed digest: %x != %x", got, wantJSON)
			}

			boltPath := filepath.Join(t.TempDir(), "state.db")
			bs, err := OpenBoltState(boltPath, testCipher(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := bs.db.Update(func(tx *bolt.Tx) error {
				return putRecord(tx, boltBucketSubSnapshots, "p/s", legacySubscriptionSnapshotV1{SchemaVersion: 1, PluginID: "p", SubscriptionID: "s", Raw: malformed})
			}); err != nil {
				t.Fatal(err)
			}
			if err := bs.Close(); err != nil {
				t.Fatal(err)
			}
			beforeBolt, err := os.ReadFile(boltPath)
			if err != nil {
				t.Fatal(err)
			}
			wantBolt := sha256.Sum256(beforeBolt)
			if reopened, err := OpenBoltState(boltPath, testCipher(t)); err == nil {
				reopened.Close()
				t.Fatal("malformed Bolt envelope accepted")
			}
			afterBolt, err := os.ReadFile(boltPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256.Sum256(afterBolt); got != wantBolt {
				t.Fatalf("failed Bolt open changed digest: %x != %x", got, wantBolt)
			}
		})
	}
}

func TestLegacyPlaintextSubscriptionSecretsMigrateInOneBoltUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	bs, err := OpenBoltState(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	legacySnapshot := legacySubscriptionSnapshotV1{SchemaVersion: 1, PluginID: "p", SubscriptionID: "s", Raw: snapshotRawCanary}
	legacyShare := model.SubscriptionShare{ID: "share", Token: "share-plaintext-canary"}
	if err := bs.db.Update(func(tx *bolt.Tx) error {
		if err := putRecord(tx, boltBucketSubSnapshots, "p/s", legacySnapshot); err != nil {
			return err
		}
		return putRecord(tx, boltBucketSubShares, "share", legacyShare)
	}); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	bs.testUpdateCalls = 0
	got, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if bs.testUpdateCalls != 1 {
		t.Fatalf("migration updates = %d, want 1", bs.testUpdateCalls)
	}
	if got.SubscriptionSnapshots["p/s"].Raw != snapshotRawCanary || got.SubscriptionShares["share"].Token != "share-plaintext-canary" {
		t.Fatalf("migrated values changed: %+v", got)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("full-Bolt migration reused the source database instead of a fresh compact replacement")
	}
	wholeFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wholeFile), snapshotRawCanary) || strings.Contains(string(wholeFile), "share-plaintext-canary") {
		t.Fatal("fresh Bolt replacement retained a plaintext canary in obsolete pages")
	}
	if err := bs.db.View(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{boltBucketSubSnapshots, boltBucketSubShares} {
			if err := tx.Bucket(bucket).ForEach(func(_, value []byte) error {
				if strings.Contains(string(value), snapshotRawCanary) || strings.Contains(string(value), "share-plaintext-canary") {
					t.Fatal("plaintext survived in authoritative Bolt records")
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionSnapshotRawEncryptedFullBoltRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	bs, err := OpenBoltState(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	state := emptyState()
	state.SubscriptionSnapshots["p/s"] = model.SubscriptionSnapshot{SchemaVersion: model.SubscriptionSnapshotSchemaVersion, PluginID: "p", SubscriptionID: "s", Raw: snapshotRawCanary, FetchedAt: time.Now().UTC()}
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

func TestRuntimeHotSubscriptionAuthorityPreventsJSONSeedResurrectionAfterDeleteAndEmpty(t *testing.T) {
	dir := t.TempDir()
	jsonPath, boltPath := filepath.Join(dir, "state.json"), filepath.Join(dir, "hot.db")
	cipher := testCipher(t)
	s, err := OpenWithCipher(jsonPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: snapshotRawCanary}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{ID: "share", Token: "stale-json-token"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: "hot-update", LastAttemptAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubscriptionShare(model.SubscriptionShare{ID: "share", Token: "hot-update-token"}); err != nil {
		t.Fatal(err)
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
	if got, ok := reopened.SubscriptionSnapshot("p", "s"); !ok || got.Raw != "hot-update" {
		t.Fatalf("stale JSON overrode authoritative hot update: %+v ok=%v", got, ok)
	}
	if got, ok := reopened.SubscriptionShare("share"); !ok || got.Token != "hot-update-token" {
		t.Fatalf("stale JSON overrode authoritative hot share: %+v ok=%v", got, ok)
	}
	if err := reopened.DeleteSubscriptionSnapshot("p", "s"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteSubscriptionShare("share"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err = OpenWithCipher(jsonPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.SubscriptionSnapshot("p", "s"); ok {
		t.Fatal("deleted hot snapshot resurrected from stale JSON seed")
	}
	if _, ok := reopened.SubscriptionShare("share"); ok {
		t.Fatal("deleted hot share resurrected from stale JSON seed")
	}
	if got := reopened.SubscriptionSnapshots(); len(got) != 0 {
		t.Fatalf("authoritative hot snapshot collection is not empty: %+v", got)
	}
	if got := reopened.SubscriptionShares(); len(got) != 0 {
		t.Fatalf("authoritative hot share collection is not empty: %+v", got)
	}
}

func TestRuntimeHotSubscriptionAuthoritySeedAndMarkerAreOneRetryableTransaction(t *testing.T) {
	for _, stage := range []string{"after_shares", "before_marker"} {
		t.Run(stage, func(t *testing.T) {
			cipher := testCipher(t)
			bs, err := OpenBoltState(filepath.Join(t.TempDir(), "hot.db"), cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer bs.Close()
			st := emptyState()
			st.SubscriptionShares["share"] = model.SubscriptionShare{ID: "share", Token: "seed-token"}
			st.SubscriptionSnapshots[model.SnapshotKey("p", "s")] = model.SubscriptionSnapshot{
				SchemaVersion: model.SubscriptionSnapshotSchemaVersion,
				PluginID:      "p", SubscriptionID: "s", Raw: snapshotRawCanary,
			}
			bs.testSubscriptionSeedFailure = func(got string) error {
				if got == stage {
					return errors.New("injected subscription seed failure")
				}
				return nil
			}
			if err := syncRuntimeBoltHotState(bs, st); err == nil {
				t.Fatal("injected initialization failure not surfaced")
			}
			initialized, err := bs.subscriptionHotAuthorityInitialized()
			if err != nil {
				t.Fatal(err)
			}
			if initialized {
				t.Fatal("failed initialization published authority marker")
			}
			rolledBack, err := bs.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			if len(rolledBack.SubscriptionShares) != 0 || len(rolledBack.SubscriptionSnapshots) != 0 {
				t.Fatalf("failed initialization published partial seed: shares=%v snapshots=%v", rolledBack.SubscriptionShares, rolledBack.SubscriptionSnapshots)
			}

			bs.testSubscriptionSeedFailure = nil
			if err := syncRuntimeBoltHotState(bs, st); err != nil {
				t.Fatal(err)
			}
			initialized, err = bs.subscriptionHotAuthorityInitialized()
			if err != nil || !initialized {
				t.Fatalf("retry authority = %v, %v", initialized, err)
			}
			seeded, err := bs.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			if seeded.SubscriptionShares["share"].Token != "seed-token" {
				t.Fatalf("retry share = %+v", seeded.SubscriptionShares["share"])
			}
			if seeded.SubscriptionSnapshots[model.SnapshotKey("p", "s")].Raw != snapshotRawCanary {
				t.Fatalf("retry snapshot = %+v", seeded.SubscriptionSnapshots)
			}
		})
	}
}

func TestRuntimeHotSubscriptionAuthorityReconcilesUnmarkedUnionByRecency(t *testing.T) {
	for _, relation := range []string{"json_newer", "bolt_newer", "tie"} {
		t.Run(relation, func(t *testing.T) {
			cipher := testCipher(t)
			bs, err := OpenBoltState(filepath.Join(t.TempDir(), "hot.db"), cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer bs.Close()
			base := time.Unix(100, 0).UTC()
			jsonAt, boltAt := base.Add(2*time.Minute), base.Add(time.Minute)
			if relation == "bolt_newer" {
				jsonAt, boltAt = boltAt, jsonAt
			} else if relation == "tie" {
				jsonAt, boltAt = base, base
			}
			jsonState, boltState := emptyState(), emptyState()
			jsonState.SubscriptionShares["same"] = model.SubscriptionShare{ID: "same", Token: "json", UpdatedAt: jsonAt}
			jsonState.SubscriptionSnapshots["p/s"] = model.SubscriptionSnapshot{SchemaVersion: model.SubscriptionSnapshotSchemaVersion, PluginID: "p", SubscriptionID: "s", Raw: "json", LastAttemptAt: jsonAt}
			boltState.SubscriptionShares["same"] = model.SubscriptionShare{ID: "same", Token: "bolt", UpdatedAt: boltAt}
			boltState.SubscriptionSnapshots["p/s"] = model.SubscriptionSnapshot{SchemaVersion: model.SubscriptionSnapshotSchemaVersion, PluginID: "p", SubscriptionID: "s", Raw: "bolt", LastAttemptAt: boltAt}
			boltState.SubscriptionShares["bolt-only"] = model.SubscriptionShare{ID: "bolt-only", Token: "bolt-only", UpdatedAt: boltAt}
			boltState.SubscriptionSnapshots["p/bolt-only"] = model.SubscriptionSnapshot{SchemaVersion: model.SubscriptionSnapshotSchemaVersion, PluginID: "p", SubscriptionID: "bolt-only", Raw: "bolt-only", LastAttemptAt: boltAt}
			jsonState.SubscriptionShares["json-only"] = model.SubscriptionShare{ID: "json-only", Token: "json-only", UpdatedAt: jsonAt}
			jsonState.SubscriptionSnapshots["p/json-only"] = model.SubscriptionSnapshot{SchemaVersion: model.SubscriptionSnapshotSchemaVersion, PluginID: "p", SubscriptionID: "json-only", Raw: "json-only", LastAttemptAt: jsonAt}
			if err := bs.importState(boltState, false); err != nil {
				t.Fatal(err)
			}
			if err := syncRuntimeBoltHotState(bs, jsonState); err != nil {
				t.Fatal(err)
			}
			got, err := bs.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			want := "json"
			if relation != "json_newer" {
				want = "bolt"
			}
			if got.SubscriptionShares["same"].Token != want || got.SubscriptionSnapshots["p/s"].Raw != want {
				t.Fatalf("overlap precedence share=%+v snapshot=%+v want=%q", got.SubscriptionShares["same"], got.SubscriptionSnapshots["p/s"], want)
			}
			if got.SubscriptionShares["bolt-only"].Token != "bolt-only" || got.SubscriptionSnapshots["p/bolt-only"].Raw != "bolt-only" {
				t.Fatalf("Bolt-only records lost: shares=%+v snapshots=%+v", got.SubscriptionShares, got.SubscriptionSnapshots)
			}
			if got.SubscriptionShares["json-only"].Token != "json-only" || got.SubscriptionSnapshots["p/json-only"].Raw != "json-only" {
				t.Fatalf("JSON-only records lost: shares=%+v snapshots=%+v", got.SubscriptionShares, got.SubscriptionSnapshots)
			}
		})
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
