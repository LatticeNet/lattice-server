package proxycore

import (
	"encoding/base64"
	"regexp"
	"testing"
)

// Mirror of the server-side reality key/short-id regexes so this package
// independently guarantees generated values are acceptable upstream.
var (
	testRealityKeyRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	testRealityShortIDRe = regexp.MustCompile(`^[0-9a-fA-F]{2,16}$`)
)

func TestGenerateRealityKeypair(t *testing.T) {
	priv, pub, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	if !testRealityKeyRe.MatchString(priv) {
		t.Fatalf("private key %q does not match reality key regex", priv)
	}
	if !testRealityKeyRe.MatchString(pub) {
		t.Fatalf("public key %q does not match reality key regex", pub)
	}
	for name, key := range map[string]string{"private": priv, "public": pub} {
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			t.Fatalf("%s key is not base64.RawURLEncoding: %v", name, err)
		}
		if len(raw) != 32 {
			t.Fatalf("%s key decodes to %d bytes, want 32", name, len(raw))
		}
	}
	// The returned public key must be the one derived from the private key.
	derived, err := RealityPublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("RealityPublicKeyFromPrivate: %v", err)
	}
	if derived != pub {
		t.Fatalf("derived public %q != returned public %q", derived, pub)
	}

	// Two generations must differ (sanity on randomness).
	priv2, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair (2): %v", err)
	}
	if priv2 == priv {
		t.Fatalf("two generated private keys are identical")
	}
}

func TestRealityPublicKeyFromPrivateAcceptsEncodings(t *testing.T) {
	priv, pub, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode priv: %v", err)
	}
	// Same key, different encodings, must all derive the same public key.
	for _, enc := range []string{
		base64.RawURLEncoding.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
	} {
		got, err := RealityPublicKeyFromPrivate(enc)
		if err != nil {
			t.Fatalf("RealityPublicKeyFromPrivate(%q): %v", enc, err)
		}
		if got != pub {
			t.Fatalf("encoding %q derived %q, want %q", enc, got, pub)
		}
	}

	if _, err := RealityPublicKeyFromPrivate("not-base64!!"); err == nil {
		t.Fatalf("expected error for invalid private key")
	}
	if _, err := RealityPublicKeyFromPrivate(base64.RawURLEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatalf("expected error for non-32-byte key")
	}
}

func TestGenerateRealityShortID(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 4, 8, 99} {
		sid, err := GenerateRealityShortID(n)
		if err != nil {
			t.Fatalf("GenerateRealityShortID(%d): %v", n, err)
		}
		if !testRealityShortIDRe.MatchString(sid) {
			t.Fatalf("short id %q (n=%d) does not match regex", sid, n)
		}
		if len(sid)%2 != 0 {
			t.Fatalf("short id %q has odd length", sid)
		}
	}
}
