package secret

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestCipher(t *testing.T) Cipher {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("gen key: %v", err)
	}
	c, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	cases := []string{
		"hello",
		"cf_token_abcdef0123456789",
		strings.Repeat("x", 4096),
		"unicode: 你好🔐",
		"with\nnewlines\tand\x00nul",
	}
	for _, pt := range cases {
		env, err := c.Encrypt(pt)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", pt, err)
		}
		if !IsEnvelope(env) {
			t.Fatalf("Encrypt(%q) did not produce an envelope: %q", pt, env)
		}
		if strings.Contains(env, pt) && pt != "" {
			t.Fatalf("ciphertext contains plaintext for %q", pt)
		}
		got, err := c.Decrypt(env)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != pt {
			t.Fatalf("round trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestEmptyStringPassesThrough(t *testing.T) {
	c := newTestCipher(t)
	env, err := c.Encrypt("")
	if err != nil || env != "" {
		t.Fatalf("Encrypt(\"\") = %q, %v; want empty", env, err)
	}
	got, err := c.Decrypt("")
	if err != nil || got != "" {
		t.Fatalf("Decrypt(\"\") = %q, %v; want empty", got, err)
	}
}

func TestNonceUniqueness(t *testing.T) {
	c := newTestCipher(t)
	const n = 1000
	seen := make(map[string]bool, n)
	for i := range n {
		env, err := c.Encrypt("same plaintext")
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if seen[env] {
			t.Fatalf("duplicate ciphertext at iteration %d — nonce reuse", i)
		}
		seen[env] = true
	}
}

func TestEncryptAlwaysFresh(t *testing.T) {
	c := newTestCipher(t)
	// Encrypt does not short-circuit on envelope-looking input; it always
	// produces fresh ciphertext. Re-encrypting an envelope yields a new
	// envelope that decrypts back to the inner envelope string.
	inner, err := c.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := c.Encrypt(inner)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped == inner {
		t.Fatal("Encrypt short-circuited on envelope-looking input; expected fresh ciphertext")
	}
	got, err := c.Decrypt(wrapped)
	if err != nil || got != inner {
		t.Fatalf("re-encrypt round trip mismatch: got %q err %v", got, err)
	}
}

func TestDecryptLegacyPlaintextPassesThrough(t *testing.T) {
	c := newTestCipher(t)
	const legacy = "plaintext-cf-token-from-before-encryption"
	got, err := c.Decrypt(legacy)
	if err != nil {
		t.Fatalf("Decrypt(legacy): %v", err)
	}
	if got != legacy {
		t.Fatalf("legacy passthrough mismatch: %q != %q", got, legacy)
	}
}

func TestTamperDetection(t *testing.T) {
	c := newTestCipher(t)
	env, err := c.Encrypt("tamper me")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env, envelopePrefix))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the ciphertext body (past the nonce).
	raw[len(raw)-1] ^= 0x01
	tampered := envelopePrefix + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext, got nil")
	}
}

func TestWrongKeyFails(t *testing.T) {
	c1 := newTestCipher(t)
	c2 := newTestCipher(t)
	env, err := c1.Encrypt("cross-key secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Decrypt(env); err == nil {
		t.Fatal("expected decrypt with wrong key to fail, got nil")
	}
}

func TestShortPrefixedValueTreatedAsPlaintext(t *testing.T) {
	c := newTestCipher(t)
	// A prefixed value too short to hold a nonce+tag cannot be a real envelope.
	// By the collision-resistance rule it is indistinguishable from legacy
	// plaintext that merely starts with the prefix, so it passes through rather
	// than erroring. (Tampering of *full-length* envelopes is still caught by
	// GCM — see TestTamperDetection / TestWrongKeyFails.)
	short := envelopePrefix + base64.RawURLEncoding.EncodeToString([]byte("tiny"))
	if IsEnvelope(short) {
		t.Fatalf("too-short prefixed value should not classify as an envelope: %q", short)
	}
	got, err := c.Decrypt(short)
	if err != nil {
		t.Fatalf("expected passthrough, got error: %v", err)
	}
	if got != short {
		t.Fatalf("passthrough mismatch: %q != %q", got, short)
	}
}

func TestNewAESGCMKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewAESGCM(make([]byte, n)); err == nil {
			t.Fatalf("NewAESGCM accepted %d-byte key; want rejection", n)
		}
	}
	if _, err := NewAESGCM(make([]byte, KeySize)); err != nil {
		t.Fatalf("NewAESGCM rejected valid %d-byte key: %v", KeySize, err)
	}
}

func TestDisabledCipherPassthrough(t *testing.T) {
	c := Disabled()
	if c.Enabled() {
		t.Fatal("Disabled().Enabled() should be false")
	}
	for _, s := range []string{"", "secret", "lat$1$whatever"} {
		env, err := c.Encrypt(s)
		if err != nil || env != s {
			t.Fatalf("disabled Encrypt(%q) = %q, %v", s, env, err)
		}
		got, err := c.Decrypt(s)
		if err != nil || got != s {
			t.Fatalf("disabled Decrypt(%q) = %q, %v", s, got, err)
		}
	}
}

// --- key resolution ------------------------------------------------------

func TestResolveEnvInlineKey(t *testing.T) {
	key := make([]byte, KeySize)
	io.ReadFull(rand.Reader, key)
	t.Setenv(EnvMasterKey, base64.StdEncoding.EncodeToString(key))
	res, err := Resolve(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "env" || !res.Cipher.Enabled() {
		t.Fatalf("unexpected resolve result: %+v", res)
	}
	// Confirm the resolved cipher uses exactly this key.
	ref, _ := NewAESGCM(key)
	env, _ := ref.Encrypt("probe")
	got, err := res.Cipher.Decrypt(env)
	if err != nil || got != "probe" {
		t.Fatalf("resolved cipher does not match env key: %q %v", got, err)
	}
}

func TestResolveEnvDisableSentinel(t *testing.T) {
	for _, v := range []string{"off", "OFF", "0", "disabled", "none"} {
		t.Setenv(EnvMasterKey, v)
		res, err := Resolve(t.TempDir(), "")
		if err != nil {
			t.Fatalf("Resolve(%q): %v", v, err)
		}
		if res.Cipher.Enabled() || res.Source != "disabled" {
			t.Fatalf("sentinel %q did not disable: %+v", v, res)
		}
	}
}

func TestResolveEnvBadKey(t *testing.T) {
	t.Setenv(EnvMasterKey, "not-a-valid-32-byte-key")
	if _, err := Resolve(t.TempDir(), ""); err == nil {
		t.Fatal("expected error for malformed env key")
	}
}

func TestResolveGeneratesKeyFile(t *testing.T) {
	dir := t.TempDir()
	os.Unsetenv(EnvMasterKey)
	os.Unsetenv(EnvMasterKeyFile)
	res, err := Resolve(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Generated || !res.Cipher.Enabled() {
		t.Fatalf("expected a generated enabled cipher: %+v", res)
	}
	kf := filepath.Join(dir, defaultKeyFile)
	info, err := os.Stat(kf)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perms = %o, want 0600", perm)
	}
	// A second Resolve must reuse (not regenerate) the same key.
	res2, err := Resolve(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Generated {
		t.Fatal("second Resolve regenerated the key file")
	}
	env, _ := res.Cipher.Encrypt("stable")
	got, err := res2.Cipher.Decrypt(env)
	if err != nil || got != "stable" {
		t.Fatalf("reused key cannot decrypt prior ciphertext: %q %v", got, err)
	}
}

func TestResolveKeyFileOverride(t *testing.T) {
	dir := t.TempDir()
	os.Unsetenv(EnvMasterKey)
	os.Unsetenv(EnvMasterKeyFile)
	key := make([]byte, KeySize)
	io.ReadFull(rand.Reader, key)
	kf := filepath.Join(dir, "custom.key")
	if err := os.WriteFile(kf, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Resolve(dir, kf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "file:"+kf {
		t.Fatalf("unexpected source: %q", res.Source)
	}
	ref, _ := NewAESGCM(key)
	env, _ := ref.Encrypt("hexkey")
	got, err := res.Cipher.Decrypt(env)
	if err != nil || got != "hexkey" {
		t.Fatalf("hex key file mismatch: %q %v", got, err)
	}
}

func TestParseKeyEncodings(t *testing.T) {
	key := make([]byte, KeySize)
	io.ReadFull(rand.Reader, key)
	encodings := map[string]string{
		"base64std":    base64.StdEncoding.EncodeToString(key),
		"base64rawurl": base64.RawURLEncoding.EncodeToString(key),
		"hex":          hex.EncodeToString(key),
		"raw":          string(key),
		"trailing-nl":  base64.StdEncoding.EncodeToString(key) + "\n",
	}
	for name, enc := range encodings {
		got, err := parseKey([]byte(enc))
		if err != nil {
			t.Fatalf("parseKey(%s): %v", name, err)
		}
		if string(got) != string(key) {
			t.Fatalf("parseKey(%s) mismatch", name)
		}
	}
	if _, err := parseKey([]byte("")); err == nil {
		t.Fatal("expected error for empty key")
	}
	if _, err := parseKey([]byte("tooshort")); err == nil {
		t.Fatal("expected error for short key")
	}
}

// TestParseKeyWhitespaceBoundaryBytes is a deterministic regression for the bug
// where TrimSpace shortened a raw key whose first/last byte was an ASCII
// whitespace value. Uses a 32-byte key starting with 0x20 (space) and ending
// with 0x0a (newline).
func TestParseKeyWhitespaceBoundaryBytes(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i + 1) // distinctive, non-zero interior
	}
	key[0] = 0x20  // leading space
	key[31] = 0x0a // trailing newline
	got, err := parseKey(key)
	if err != nil {
		t.Fatalf("parseKey rejected a valid whitespace-boundary raw key: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("parseKey corrupted whitespace-boundary key: got %x want %x", got, key)
	}
	// The returned slice must be an independent copy (caller may retain it).
	got[0] = 0xff
	if key[0] == 0xff {
		t.Fatal("parseKey returned an aliased slice, not a copy")
	}
	// A genuinely whitespace-wrapped base64 key (trailing newline) still works.
	enc := base64.StdEncoding.EncodeToString(key) + "\n"
	if k2, err := parseKey([]byte(enc)); err != nil || string(k2) != string(key) {
		t.Fatalf("parseKey(base64+newline) = %x, %v", k2, err)
	}
}

// TestEnvelopeCollisionResistance is a regression for the bare-prefix
// discriminator bug: operator plaintext beginning with the envelope prefix must
// still be encrypted (not stored verbatim) and must round-trip, and a legacy
// plaintext beginning with the prefix that is not a real envelope must decrypt
// to itself rather than erroring.
func TestEnvelopeCollisionResistance(t *testing.T) {
	c := newTestCipher(t)
	// Plaintexts that begin with the envelope prefix but are NOT structurally
	// valid envelopes (non-base64url remainder, or too short to hold a
	// nonce+tag). These must classify as plaintext, encrypt to a fresh
	// envelope, and survive a load-time legacy passthrough.
	collisions := []string{
		envelopePrefix + "hello",     // prefix + non-base64url ('l','o' ok but...) -> short decode anyway
		envelopePrefix,               // bare prefix
		envelopePrefix + "AAAA",      // prefix + valid base64 decoding < nonce+tag
		"lat$1$tok_live:AbC!def",     // realistic token with non-base64url chars (':','!')
		"lat$1$smtp pass with space", // spaces are not base64url
	}
	for _, pt := range collisions {
		if IsEnvelope(pt) {
			t.Fatalf("plaintext %q wrongly classified as an envelope", pt)
		}
		env, err := c.Encrypt(pt)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", pt, err)
		}
		if env == pt {
			t.Fatalf("Encrypt left prefix-colliding plaintext verbatim (stored in cleartext): %q", pt)
		}
		if !IsEnvelope(env) {
			t.Fatalf("Encrypt(%q) did not produce a real envelope", pt)
		}
		got, err := c.Decrypt(env)
		if err != nil || got != pt {
			t.Fatalf("round trip of colliding plaintext failed: got %q err %v", got, err)
		}
		// Legacy passthrough: the colliding plaintext, fed directly to Decrypt
		// as if loaded from a pre-encryption file, must come back unchanged.
		legacy, err := c.Decrypt(pt)
		if err != nil {
			t.Fatalf("Decrypt(legacy %q) errored instead of passthrough: %v", pt, err)
		}
		if legacy != pt {
			t.Fatalf("legacy passthrough mismatch: %q != %q", legacy, pt)
		}
	}

	// Documented residual: a value that is the prefix followed by a genuinely
	// valid base64url body of >= nonce+tag bytes is structurally indistinguish-
	// able from ciphertext. The store never hits this on the *write* path
	// (Encrypt always re-encrypts in-memory plaintext), so such a secret still
	// round-trips through Save/load:
	residual := envelopePrefix + strings.Repeat("a", 100) // valid base64url, 75 bytes
	if !IsEnvelope(residual) {
		t.Fatal("precondition: residual case should look like an envelope")
	}
	enc, err := c.Encrypt(residual) // store path: always encrypts
	if err != nil || enc == residual || !IsEnvelope(enc) {
		t.Fatalf("residual must still encrypt: %q %v", enc, err)
	}
	if got, err := c.Decrypt(enc); err != nil || got != residual {
		t.Fatalf("residual round trip failed: %q %v", got, err)
	}
}
