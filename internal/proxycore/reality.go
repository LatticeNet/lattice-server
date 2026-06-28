package proxycore

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// REALITY keys are X25519 keypairs encoded with base64.RawURLEncoding — the exact
// format sing-box (`sing-box generate reality-keypair`) and xray (`xray x25519`)
// expect for an inbound's private_key and the matching client public key (pbk).
//
// Generating them server-side (design-09 Phase B) removes the prior requirement
// that an operator run sing-box/xray by hand to obtain a private key before they
// can create a REALITY inbound.

// GenerateRealityKeypair returns a fresh X25519 keypair as base64.RawURLEncoding
// strings. The 32-byte keys encode to 43 chars of [A-Za-z0-9_-], satisfying the
// server's reality key regex.
func GenerateRealityKeypair() (privateKey, publicKey string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate reality keypair: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv.Bytes()), enc.EncodeToString(priv.PublicKey().Bytes()), nil
}

// RealityPublicKeyFromPrivate derives the base64.RawURLEncoding public key for an
// operator-supplied X25519 private key. It accepts the key in raw/std base64 with
// or without padding, and always returns the public key in the canonical
// base64.RawURLEncoding form used in subscription links.
func RealityPublicKeyFromPrivate(privateKey string) (string, error) {
	raw, err := decodeRealityKey(privateKey)
	if err != nil {
		return "", err
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid reality private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// GenerateRealityShortID returns a random REALITY short_id: a lowercase,
// even-length hex string. n is the number of random bytes (clamped to 1..8, so
// the result is 2..16 hex chars), satisfying the short-id regex + even-length
// rule the core enforces.
func GenerateRealityShortID(n int) (string, error) {
	switch {
	case n < 1:
		n = 4
	case n > 8:
		n = 8
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate reality short id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// decodeRealityKey decodes a base64 X25519 key in any common encoding and
// verifies it is exactly 32 bytes.
func decodeRealityKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("reality key must be base64-encoded 32 bytes")
}
