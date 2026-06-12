package store

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
)

func testCipher(t *testing.T) secret.Cipher {
	t.Helper()
	key := make([]byte, secret.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	c, err := secret.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// seedSecrets populates one of each secret-bearing record with known plaintext.
func seedSecrets(t *testing.T, s *Store) {
	t.Helper()
	if err := s.UpsertUser(model.User{ID: "u1", Username: "admin", TOTPSecret: totpPlain}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDDNSProfile(model.DDNSProfile{
		ID: "d1", Name: "home", Provider: "cloudflare",
		CFAPIToken: cfTokenPlain, WebhookHeaders: webhookHdrPlain,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNotifyChannel(model.NotifyChannel{
		ID: "n1", Name: "tg", Kind: "telegram",
		Config: map[string]string{"bot_token": botTokenPlain, "chat_id": chatIDPlain},
	}); err != nil {
		t.Fatal(err)
	}
}

func findNotify(s *Store, id string) *model.NotifyChannel {
	for _, n := range s.NotifyChannels() {
		if n.ID == id {
			nn := n
			return &nn
		}
	}
	return nil
}

const (
	totpPlain       = "JBSWY3DPEHPK3PXP"
	cfTokenPlain    = "cf-secret-token-9f8e7d6c5b4a"
	webhookHdrPlain = `{"Authorization":"Bearer xyz123"}`
	botTokenPlain   = "123456:AAtertoken-bot-secret"
	chatIDPlain     = "-1001234567890"
)

func TestEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	c := testCipher(t)

	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	seedSecrets(t, s)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := string(raw)

	// No plaintext secret may appear on disk.
	for _, leak := range []string{totpPlain, cfTokenPlain, webhookHdrPlain, botTokenPlain, chatIDPlain} {
		if strings.Contains(disk, leak) {
			t.Fatalf("plaintext secret leaked to disk: %q", leak)
		}
	}
	// Envelopes must be present.
	if !strings.Contains(disk, "lat$1$") {
		t.Fatal("expected encrypted envelopes on disk, found none")
	}
	// Non-secret fields stay readable (we did not over-encrypt).
	for _, plain := range []string{"admin", "home", "cloudflare", "telegram"} {
		if !strings.Contains(disk, plain) {
			t.Fatalf("expected non-secret field %q to remain readable on disk", plain)
		}
	}
}

func TestReopenDecryptsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	c := testCipher(t)

	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	seedSecrets(t, s)

	s2, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	u, ok := s2.User("u1")
	if !ok || u.TOTPSecret != totpPlain {
		t.Fatalf("totp not recovered: %+v ok=%v", u.TOTPSecret, ok)
	}
	d, ok := s2.DDNSProfile("d1")
	if !ok || d.CFAPIToken != cfTokenPlain || d.WebhookHeaders != webhookHdrPlain {
		t.Fatalf("ddns secrets not recovered: %+v ok=%v", d, ok)
	}
	n := findNotify(s2, "n1")
	if n == nil || n.Config["bot_token"] != botTokenPlain || n.Config["chat_id"] != chatIDPlain {
		t.Fatalf("notify config not recovered: %+v", n)
	}
}

func TestWrongKeyFailsToOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	seedSecrets(t, s)

	if _, err := OpenWithCipher(path, testCipher(t)); err == nil {
		t.Fatal("expected open with wrong key to fail")
	}
}

func TestLegacyPlaintextMigratesOnSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Write a legacy (unencrypted) state file using a disabled cipher.
	legacy, err := OpenWithCipher(path, secret.Disabled())
	if err != nil {
		t.Fatal(err)
	}
	seedSecrets(t, legacy)
	rawLegacy, _ := os.ReadFile(path)
	if !strings.Contains(string(rawLegacy), cfTokenPlain) {
		t.Fatal("precondition: legacy file should contain plaintext")
	}

	// Open the legacy file with a real cipher: it must load (plaintext
	// passthrough) and recover the secrets.
	c := testCipher(t)
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatalf("open legacy with cipher: %v", err)
	}
	d, ok := s.DDNSProfile("d1")
	if !ok || d.CFAPIToken != cfTokenPlain {
		t.Fatalf("legacy secret not loaded: %+v", d)
	}

	// Any mutation triggers Save, which must now encrypt the file.
	if err := s.UpsertUser(model.User{ID: "u2", Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	rawAfter, _ := os.ReadFile(path)
	if strings.Contains(string(rawAfter), cfTokenPlain) {
		t.Fatal("legacy plaintext was not encrypted after save")
	}
	if !strings.Contains(string(rawAfter), "lat$1$") {
		t.Fatal("expected envelopes after migration save")
	}
}

func TestLostKeyGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	seedSecrets(t, s)

	// Opening encrypted state with a disabled cipher must refuse, not corrupt.
	_, err = OpenWithCipher(path, secret.Disabled())
	if err == nil {
		t.Fatal("expected lost-key guard to reject disabled cipher on encrypted state")
	}
	if !strings.Contains(err.Error(), "master key") {
		t.Fatalf("error should mention master key, got: %v", err)
	}
}

func TestPrefixCollidingSecretRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	c := testCipher(t)

	const colliding = "lat$1$this-looks-like-an-envelope-but-is-a-real-token"
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDDNSProfile(model.DDNSProfile{ID: "d1", CFAPIToken: colliding}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNotifyChannel(model.NotifyChannel{
		ID: "n1", Config: map[string]string{"token": colliding},
	}); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), colliding) {
		t.Fatal("prefix-colliding secret was stored in cleartext")
	}

	s2, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	d, _ := s2.DDNSProfile("d1")
	if d.CFAPIToken != colliding {
		t.Fatalf("colliding cf token not recovered: %q", d.CFAPIToken)
	}
	if n := findNotify(s2, "n1"); n == nil || n.Config["token"] != colliding {
		t.Fatalf("colliding notify token not recovered: %+v", n)
	}
}

func TestDataDirIsPrivate(t *testing.T) {
	os.Unsetenv(secret.EnvMasterKey)
	os.Unsetenv(secret.EnvMasterKeyFile)
	dir := t.TempDir()
	sub := filepath.Join(dir, "state") // does not exist yet
	path := filepath.Join(sub, "state.json")

	// Auto-resolve creates the data dir (for the generated key) at 0700; Save
	// also uses 0700. Neither path may produce a world-traversable 0755 dir.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUser(model.User{ID: "u1", Username: "a"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("data dir perms = %o, want 0700", perm)
	}
}

func TestOpenAutoResolvesAndPersistsEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	t.Setenv(secret.EnvMasterKey, "") // ensure env path not taken
	os.Unsetenv(secret.EnvMasterKey)
	os.Unsetenv(secret.EnvMasterKeyFile)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open auto-resolve: %v", err)
	}
	seedSecrets(t, s)

	// A master.key file should have been generated alongside the state.
	if _, err := os.Stat(filepath.Join(dir, "master.key")); err != nil {
		t.Fatalf("master.key not generated: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), cfTokenPlain) {
		t.Fatal("auto-resolved store left plaintext on disk")
	}

	// Reopen via Open (reads the generated key) and recover the secret.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen auto-resolve: %v", err)
	}
	d, ok := s2.DDNSProfile("d1")
	if !ok || d.CFAPIToken != cfTokenPlain {
		t.Fatalf("auto-resolve round trip failed: %+v", d)
	}
}
