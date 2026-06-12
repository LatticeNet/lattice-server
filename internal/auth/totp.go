package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) second factor. Implemented on the standard library only
// (HMAC-SHA1 + base32) — the algorithm is fully specified and verifiable against
// the RFC 6238 test vectors, so it does not justify an external dependency.

const (
	totpDigits      = 6
	totpPeriodSecs  = 30
	totpSecretBytes = 20 // 160-bit, the RFC 4226 recommended seed length
	// recoveryCodeBytes yields a >=12-char base64url string so the codes can be
	// hashed with HashSecret (which requires at least 12 characters).
	recoveryCodeBytes = 10
)

var totpEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh base32 (unpadded) shared secret.
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpEnc.EncodeToString(buf), nil
}

// TOTPCodeAt returns the 6-digit code for a specific instant. Exposed mainly so
// tests can assert against the RFC 6238 vectors and so enrollment can preview.
func TOTPCodeAt(secret string, t time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix())/totpPeriodSecs), nil
}

// ValidateTOTP reports whether code matches secret at time t, tolerating one
// step of clock skew on either side. The comparison is constant-time.
func ValidateTOTP(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil || len(key) == 0 {
		return false
	}
	counter := uint64(t.Unix()) / totpPeriodSecs
	steps := []uint64{counter, counter + 1}
	if counter > 0 {
		steps = append(steps, counter-1)
	}
	ok := false
	for _, c := range steps {
		// Compare every candidate (no early return) to keep timing uniform.
		if subtle.ConstantTimeCompare([]byte(hotp(key, c)), []byte(code)) == 1 {
			ok = true
		}
	}
	return ok
}

// OTPAuthURI builds the otpauth:// URI an authenticator app consumes. The issuer
// and account are shown to the user; the secret is the base32 shared key.
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// GenerateRecoveryCodes returns n single-use recovery codes shown to the user
// exactly once; only their HashSecret hashes are persisted.
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		code, err := NewRandomToken(recoveryCodeBytes)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// HashRecoveryCode hashes a recovery code for storage. Recovery codes carry ~80
// bits of entropy, so a fast SHA-256 (not a slow password KDF) is sufficient and
// keeps the constant-time, lock-held comparison in the store cheap.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	trunc := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	digits := []byte("0123456789")
	out := make([]byte, totpDigits)
	v := trunc % 1_000_000
	for i := totpDigits - 1; i >= 0; i-- {
		out[i] = digits[v%10]
		v /= 10
	}
	return string(out)
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""), "="))
	return totpEnc.DecodeString(s)
}

// TOTPChallenge is a short-lived, single-use gate issued after a first factor
// (password or OIDC) succeeds but before a session is granted to a 2FA user. It
// is store-backed and IP-bound, mirroring Session.
type TOTPChallenge struct {
	ID        string
	UserID    string
	ClientIP  string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
	// Attempts counts failed second-factor submissions; the store burns the
	// challenge once it reaches the per-challenge cap.
	Attempts int
}

// NewTOTPChallenge mints a challenge bound to a user and the requesting client.
func NewTOTPChallenge(userID, clientIP string, ttl time.Duration) (TOTPChallenge, error) {
	id, err := NewRandomToken(32)
	if err != nil {
		return TOTPChallenge{}, err
	}
	now := time.Now().UTC()
	return TOTPChallenge{
		ID:        id,
		UserID:    userID,
		ClientIP:  clientIP,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}, nil
}

// Active reports whether the challenge can still be redeemed at now.
func (c TOTPChallenge) Active(now time.Time) bool {
	return !c.Used && !c.ExpiresAt.Before(now)
}
