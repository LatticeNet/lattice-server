// Package secret provides authenticated envelope encryption for sensitive
// values that the server persists at rest (TOTP secrets, Cloudflare API
// tokens, notification credentials, ...).
//
// The threat model is disk-at-rest exposure: a backup, snapshot, or stray copy
// of the state file must not leak usable credentials. It is NOT a defense
// against an attacker with live process memory or the master key itself.
//
// Design choices:
//   - AES-256-GCM (AEAD): confidentiality + integrity in one primitive. A
//     tampered or truncated ciphertext fails to open instead of returning
//     garbage.
//   - A fresh 96-bit random nonce per Encrypt call, prepended to the
//     ciphertext. GCM nonces must never repeat under the same key; random
//     nonces are safe far below the birthday bound for our volume.
//   - A versioned, self-identifying envelope prefix so we can (a) tell
//     ciphertext from legacy plaintext during migration and (b) evolve the
//     scheme later without ambiguity.
//   - Empty strings pass through unchanged so encoding/json `omitempty`
//     semantics are preserved and we never grow empty fields.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// envelopePrefix marks a value as produced by this package, version 1. It is
// chosen to be vanishingly unlikely to collide with any real secret (CF tokens,
// bot tokens, etc. never start with "lat$1$").
const envelopePrefix = "lat$1$"

// KeySize is the required master-key length: AES-256.
const KeySize = 32

// nonceSize is the standard GCM nonce length (96 bits).
const nonceSize = 12

// gcmTagSize is the AES-GCM authentication tag length (128 bits). A well-formed
// envelope therefore carries at least nonceSize+gcmTagSize bytes after the
// prefix (an empty plaintext still yields a 16-byte tag).
const gcmTagSize = 16

// Cipher transforms a plaintext secret into a persistable envelope and back.
// Implementations must be safe for concurrent use.
type Cipher interface {
	// Encrypt returns a fresh envelope for plaintext (a new random nonce every
	// call). Empty input returns empty output. Encrypt does NOT inspect its
	// input for an existing envelope: callers must hold plaintext. This avoids
	// an in-band "is this already encrypted?" heuristic that operator-supplied
	// secrets could collide with. The store upholds this by keeping in-memory
	// state decrypted at all times.
	Encrypt(plaintext string) (string, error)
	// Decrypt reverses Encrypt. Input that is not an envelope is returned
	// unchanged so pre-encryption (legacy plaintext) state loads cleanly and
	// gets encrypted on the next save. Envelope input that fails
	// authentication (tamper or wrong key) returns an error.
	Decrypt(envelope string) (string, error)
	// Enabled reports whether this cipher actually encrypts. A disabled cipher
	// is a passthrough used for in-memory stores and explicit opt-out.
	Enabled() bool
}

// IsEnvelope reports whether s is a well-formed envelope produced by this
// package: the version prefix followed by base64url that decodes to at least a
// nonce + GCM tag. The structural check (not a bare prefix match) prevents
// operator-supplied plaintext that merely starts with the prefix from being
// mistaken for ciphertext — which would otherwise either skip encryption in
// Encrypt or be treated as corrupt-on-load in Decrypt.
func IsEnvelope(s string) bool {
	if !strings.HasPrefix(s, envelopePrefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[len(envelopePrefix):])
	if err != nil {
		return false
	}
	return len(raw) >= nonceSize+gcmTagSize
}

// --- disabled (passthrough) cipher ---------------------------------------

type disabledCipher struct{}

// Disabled returns a passthrough Cipher that performs no encryption. It is used
// for in-memory stores (nothing is persisted) and for explicit operator
// opt-out. It returns its input verbatim in both directions; the store is
// responsible for warning if it ever hands a real envelope to a disabled
// cipher (which would indicate a lost key).
func Disabled() Cipher { return disabledCipher{} }

func (disabledCipher) Encrypt(plaintext string) (string, error) { return plaintext, nil }
func (disabledCipher) Decrypt(envelope string) (string, error)  { return envelope, nil }
func (disabledCipher) Enabled() bool                            { return false }

// --- AES-256-GCM cipher --------------------------------------------------

type aesGCM struct {
	aead cipher.AEAD
}

// NewAESGCM builds a Cipher from a 32-byte key.
func NewAESGCM(key []byte) (Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secret: master key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: new gcm: %w", err)
	}
	return &aesGCM{aead: aead}, nil
}

func (c *aesGCM) Enabled() bool { return true }

func (c *aesGCM) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secret: read nonce: %w", err)
	}
	sealed := c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	buf := make([]byte, 0, len(nonce)+len(sealed))
	buf = append(buf, nonce...)
	buf = append(buf, sealed...)
	return envelopePrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func (c *aesGCM) Decrypt(envelope string) (string, error) {
	if envelope == "" {
		return "", nil
	}
	if !IsEnvelope(envelope) {
		// Legacy plaintext (pre-encryption state). Pass through; it will be
		// encrypted on the next save.
		return envelope, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, envelopePrefix))
	if err != nil {
		return "", fmt.Errorf("secret: decode envelope: %w", err)
	}
	if len(raw) < nonceSize+gcmTagSize {
		return "", errors.New("secret: envelope too short")
	}
	nonce, sealed := raw[:nonceSize], raw[nonceSize:]
	plain, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("secret: authentication failed (tampered ciphertext or wrong master key): %w", err)
	}
	return string(plain), nil
}

// --- key resolution ------------------------------------------------------

// EnvMasterKey holds an inline master key (base64, hex, or raw 32 bytes), or
// one of the disable sentinels. Highest precedence — intended for KMS / secret
// manager injection.
const EnvMasterKey = "LATTICE_MASTER_KEY"

// EnvMasterKeyFile points at a file containing the master key.
const EnvMasterKeyFile = "LATTICE_MASTER_KEY_FILE"

// defaultKeyFile is the basename auto-managed under the data directory when no
// key is supplied via env or flag.
const defaultKeyFile = "master.key"

// DefaultKeyFile is the basename auto-managed under the data directory when no
// key is supplied via env or flag. It is exported for internal ops tooling that
// must refuse accidental key generation but still follow the server convention.
const DefaultKeyFile = defaultKeyFile

var disableSentinels = map[string]bool{
	"off": true, "0": true, "no": true, "none": true, "disable": true, "disabled": true,
}

// ResolveResult reports how a Cipher was obtained, for startup logging.
type ResolveResult struct {
	Cipher      Cipher
	Source      string // "env", "file:<path>", "generated:<path>", "disabled"
	Generated   bool   // a new key file was created
	KeyFilePath string // populated for file/generated sources
}

// Resolve builds a Cipher using, in precedence order:
//  1. $LATTICE_MASTER_KEY (a disable sentinel yields a passthrough cipher)
//  2. keyFileOverride argument, else $LATTICE_MASTER_KEY_FILE
//  3. <dataDir>/master.key — read if present, otherwise generated (0600)
//
// dataDir is only consulted for case 3.
func Resolve(dataDir, keyFileOverride string) (ResolveResult, error) {
	if v, ok := os.LookupEnv(EnvMasterKey); ok {
		trimmed := strings.TrimSpace(v)
		if disableSentinels[strings.ToLower(trimmed)] {
			return ResolveResult{Cipher: Disabled(), Source: "disabled"}, nil
		}
		key, err := parseKey([]byte(trimmed))
		if err != nil {
			return ResolveResult{}, fmt.Errorf("secret: %s: %w", EnvMasterKey, err)
		}
		c, err := NewAESGCM(key)
		if err != nil {
			return ResolveResult{}, err
		}
		return ResolveResult{Cipher: c, Source: "env"}, nil
	}

	path := keyFileOverride
	if path == "" {
		path = os.Getenv(EnvMasterKeyFile)
	}
	if path != "" {
		return resolveFromFile(path, false)
	}

	if dataDir == "" {
		// No persistence target; nothing to protect.
		return ResolveResult{Cipher: Disabled(), Source: "disabled"}, nil
	}
	return resolveFromFile(filepath.Join(dataDir, defaultKeyFile), true)
}

// resolveFromFile reads the key file, or — when generate is true and the file
// is absent — creates a new random key with 0600 permissions.
func resolveFromFile(path string, generate bool) (ResolveResult, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, perr := parseKey(data)
		if perr != nil {
			return ResolveResult{}, fmt.Errorf("secret: key file %s: %w", path, perr)
		}
		c, cerr := NewAESGCM(key)
		if cerr != nil {
			return ResolveResult{}, cerr
		}
		return ResolveResult{Cipher: c, Source: "file:" + path, KeyFilePath: path}, nil
	case errors.Is(err, os.ErrNotExist) && generate:
		key, gerr := generateKeyFile(path)
		if gerr != nil {
			return ResolveResult{}, gerr
		}
		c, cerr := NewAESGCM(key)
		if cerr != nil {
			return ResolveResult{}, cerr
		}
		return ResolveResult{Cipher: c, Source: "generated:" + path, Generated: true, KeyFilePath: path}, nil
	default:
		return ResolveResult{}, fmt.Errorf("secret: read key file %s: %w", path, err)
	}
}

// generateKeyFile writes a fresh 32-byte key (base64) to path with 0600,
// creating the parent directory if needed, and returns the raw key.
func generateKeyFile(path string) ([]byte, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("secret: mkdir for key file: %w", err)
		}
	}
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("secret: generate key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key) + "\n"
	// O_EXCL so we never clobber a concurrently-created key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		// Lost a race or pre-existing; re-read rather than overwrite.
		if errors.Is(err, os.ErrExist) {
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil, fmt.Errorf("secret: read key file after race: %w", rerr)
			}
			return parseKey(data)
		}
		return nil, fmt.Errorf("secret: create key file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(encoded); err != nil {
		return nil, fmt.Errorf("secret: write key file: %w", err)
	}
	return key, nil
}

// parseKey accepts a 32-byte key encoded as base64 (std or raw-url), hex, or
// supplied raw, tolerating surrounding whitespace/newlines on the encoded forms.
//
// The exact-length raw check runs first on the UNTRIMMED bytes: a raw 32-byte
// key is unambiguous (base64/hex of 32 bytes is 43, 44, or 64 chars, never 32),
// and checking before TrimSpace is essential — otherwise a key whose first or
// last byte happens to be an ASCII whitespace value (~4.6% of random keys)
// would be silently shortened below 32 bytes and rejected, a non-deterministic
// boot failure.
func parseKey(data []byte) ([]byte, error) {
	if len(data) == KeySize {
		return append([]byte(nil), data...), nil
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil, errors.New("empty key")
	}
	for _, dec := range []func(string) ([]byte, error){
		func(x string) ([]byte, error) { return base64.StdEncoding.DecodeString(x) },
		func(x string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(x) },
		func(x string) ([]byte, error) { return base64.URLEncoding.DecodeString(x) },
		func(x string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(x) },
		hex.DecodeString,
	} {
		if k, err := dec(s); err == nil && len(k) == KeySize {
			return k, nil
		}
	}
	// Raw key wrapped in surrounding whitespace (e.g. a key file with a trailing
	// newline) whose own content bytes are not whitespace.
	if len(s) == KeySize {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("key must decode to %d bytes (base64/hex) or be exactly %d raw bytes", KeySize, KeySize)
}
