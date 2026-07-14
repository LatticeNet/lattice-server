package store

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

func secretStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	key := make([]byte, secret.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := secret.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.cipher = cipher
	return st, path
}

// The whole point of a secret store is that the secret is not on the disk. A new State
// collection is serialized into state.json by default, so forgetting to extend
// encryptedState would silently write every plugin credential in cleartext — and no
// type or existing test would notice. This is that test.
func TestPluginSecretIsEncryptedOnDisk(t *testing.T) {
	st, path := secretStore(t)
	const plaintext = "wg-private-key-AAAABBBBCCCCDDDD"

	if err := st.PutPluginSecret(model.KVEntry{
		Bucket: "pluginsecret:latticenet.wireguard", Key: "node-a.privkey", Value: plaintext,
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), plaintext) {
		t.Fatal("plugin secret was written to state.json in cleartext")
	}

	// It must be a real envelope, not merely absent or mangled.
	var persisted struct {
		PluginSecrets map[string]model.KVEntry `json:"plugin_secrets"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	entry, ok := persisted.PluginSecrets["pluginsecret:latticenet.wireguard/node-a.privkey"]
	if !ok {
		t.Fatal("plugin secret missing from persisted state")
	}
	if !secret.IsEnvelope(entry.Value) {
		t.Fatalf("persisted plugin secret is not an encryption envelope: %q", entry.Value)
	}
	// The key name is not the secret and stays readable, which is what lets the store
	// look one up without decrypting the collection.
	if entry.Key != "node-a.privkey" {
		t.Fatalf("unexpected key: %q", entry.Key)
	}

	// In-memory state stays plaintext (the store's invariant), so a read returns the
	// value directly.
	got, ok := st.PluginSecret("pluginsecret:latticenet.wireguard", "node-a.privkey")
	if !ok || got.Value != plaintext {
		t.Fatalf("in-memory read did not return the plaintext: %+v", got)
	}

	// And the crypto boundary round-trips: what encryptedState seals, decryptState
	// opens, back to the exact plaintext.
	sealed, err := encryptedState(st.state, st.cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := decryptState(&sealed, st.cipher); err != nil {
		t.Fatal(err)
	}
	back, ok := sealed.PluginSecrets["pluginsecret:latticenet.wireguard/node-a.privkey"]
	if !ok || back.Value != plaintext {
		t.Fatalf("secret did not survive an encrypt/decrypt round trip: %+v", back)
	}
}

// stateHasEnvelope is the lost-master-key guard. If the secrets collection is not
// covered, losing the key degrades to handing envelope strings back to plugins as if
// they were the secret, instead of refusing to start.
func TestPluginSecretCountsTowardLostMasterKeyGuard(t *testing.T) {
	store, _ := secretStore(t)
	st := emptyState()
	if stateHasEnvelope(&st) {
		t.Fatal("empty state must not look encrypted")
	}
	// A real envelope: IsEnvelope is a structural check, so a hand-written string is
	// not good enough to prove the guard sees it.
	sealed, err := store.cipher.Encrypt("wg-private-key")
	if err != nil {
		t.Fatal(err)
	}
	st.PluginSecrets["pluginsecret:x/y"] = model.KVEntry{Bucket: "pluginsecret:x", Key: "y", Value: sealed}
	if !stateHasEnvelope(&st) {
		t.Fatal("an encrypted plugin secret must trip the lost-master-key guard")
	}
}

func TestPluginSecretBucketIsBounded(t *testing.T) {
	st, _ := secretStore(t)
	for i := range MaxPluginSecretsPerBucket {
		if err := st.PutPluginSecret(model.KVEntry{
			Bucket: "pluginsecret:p", Key: string(rune('a'+i%26)) + strings.Repeat("x", i/26+1), Value: "v",
		}); err != nil {
			t.Fatalf("entry %d should fit: %v", i, err)
		}
	}
	err := st.PutPluginSecret(model.KVEntry{Bucket: "pluginsecret:p", Key: "one-too-many", Value: "v"})
	if err == nil {
		t.Fatal("a plugin must not be able to grow its vault without bound")
	}
	// Overwriting an existing key is still allowed at the cap.
	if err := st.PutPluginSecret(model.KVEntry{Bucket: "pluginsecret:p", Key: "ax", Value: "v2"}); err != nil {
		t.Fatalf("overwrite at the cap must be allowed: %v", err)
	}
}

func TestPurgePluginSecretsRemovesOnlyThatPluginsVault(t *testing.T) {
	st, _ := secretStore(t)
	for _, e := range []model.KVEntry{
		{Bucket: "pluginsecret:a", Key: "k", Value: "a-secret"},
		{Bucket: "pluginsecret:b", Key: "k", Value: "b-secret"},
	} {
		if err := st.PutPluginSecret(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PurgePluginSecrets("pluginsecret:a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.PluginSecret("pluginsecret:a", "k"); ok {
		t.Fatal("purged vault still readable")
	}
	if got, ok := st.PluginSecret("pluginsecret:b", "k"); !ok || got.Value != "b-secret" {
		t.Fatal("purging one plugin's vault removed another's")
	}
}
