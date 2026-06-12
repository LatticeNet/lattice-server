package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestRunMigrationCLIRoundTrip(t *testing.T) {
	clearMigrationKeyEnv(t)
	dir := t.TempDir()
	c := writeMigrationMasterKey(t, dir)
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state.db")
	exportPath := filepath.Join(dir, "state.export.json")

	st := store.State{
		Users: map[string]model.User{
			"u1": {ID: "u1", Username: "admin", TOTPSecret: "totp-secret", CreatedAt: time.Unix(1_700_000_001, 0).UTC()},
		},
		Nodes: map[string]model.Node{
			"n1": {ID: "n1", Name: "hub", TokenHash: "node-token-hash"},
		},
		DDNS: map[string]model.DDNSProfile{
			"d1": {ID: "d1", Provider: "cloudflare", CFAPIToken: "cf-secret"},
		},
		NotifyChannels: map[string]model.NotifyChannel{
			"ch1": {ID: "ch1", Kind: "telegram", Config: map[string]string{"bot_token": "bot-secret"}},
		},
		OIDCProviders: map[string]model.OIDCProvider{
			"oidc": {ID: "oidc", Issuer: "https://idp.example", ClientID: "client", ClientSecret: "oidc-secret"},
		},
	}
	if err := store.WriteJSONState(jsonPath, st, c, store.MigrationOptions{}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runMigrationCLI([]string{"json-to-bolt", "-json", jsonPath, "-bolt", boltPath}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "migrated JSON state") || !strings.Contains(out.String(), "overwrite=false") {
		t.Fatalf("unexpected json-to-bolt output: %q", out.String())
	}
	rawBolt, err := os.ReadFile(boltPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawBolt, []byte("cf-secret")) || bytes.Contains(rawBolt, []byte("oidc-secret")) {
		t.Fatal("bbolt migration leaked plaintext secrets")
	}

	out.Reset()
	if err := runMigrationCLI([]string{"bolt-to-json", "-bolt", boltPath, "-json", exportPath}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "exported bbolt state") {
		t.Fatalf("unexpected bolt-to-json output: %q", out.String())
	}
	rawExport, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawExport, []byte("bot-secret")) || bytes.Contains(rawExport, []byte("oidc-secret")) {
		t.Fatal("JSON export leaked plaintext secrets")
	}
	got, err := store.LoadJSONState(exportPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if got.Users["u1"].TOTPSecret != "totp-secret" || got.NotifyChannels["ch1"].Config["bot_token"] != "bot-secret" {
		t.Fatalf("exported state did not decrypt correctly: %+v", got)
	}
}

func TestRunMigrationCLIRefusesToGenerateMissingMasterKey(t *testing.T) {
	clearMigrationKeyEnv(t)
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state.db")
	if err := os.WriteFile(jsonPath, []byte(`{"users":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runMigrationCLI([]string{"json-to-bolt", "-json", jsonPath, "-bolt", boltPath}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected missing master key to fail")
	}
	if !strings.Contains(err.Error(), "master key file") {
		t.Fatalf("error should explain the missing key, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, secret.DefaultKeyFile)); !errorsIsNotExist(err) {
		t.Fatalf("migration CLI must not generate master.key, stat err=%v", err)
	}
	if _, err := os.Stat(boltPath); !errorsIsNotExist(err) {
		t.Fatalf("failed migration should not create bbolt target, stat err=%v", err)
	}
}

func TestRunMigrationCLIRejectsAmbiguousJSONPath(t *testing.T) {
	clearMigrationKeyEnv(t)
	err := runMigrationCLI([]string{"json-to-bolt", "-json", "a.json", "-data", "b.json", "-bolt", "state.db"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-json and -data") {
		t.Fatalf("expected -json/-data conflict, got %v", err)
	}
}

func clearMigrationKeyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{secret.EnvMasterKey, secret.EnvMasterKeyFile} {
		key := key
		old, ok := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if ok {
				_ = os.Setenv(key, old)
				return
			}
			_ = os.Unsetenv(key)
		})
	}
}

func writeMigrationMasterKey(t *testing.T, dir string) secret.Cipher {
	t.Helper()
	key := make([]byte, secret.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, secret.DefaultKeyFile), []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := secret.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
