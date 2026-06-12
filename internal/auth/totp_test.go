package auth

import (
	"encoding/base32"
	"testing"
	"time"
)

// rfc6238Secret is the SHA-1 seed from RFC 6238 Appendix B ("12345678901234567890").
func rfc6238Secret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
}

func TestTOTPCodeMatchesRFC6238Vectors(t *testing.T) {
	secret := rfc6238Secret()
	// RFC 6238 Appendix B vectors are 8-digit SHA1 codes; the 6-digit code is the
	// low 6 digits of each.
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tc := range cases {
		got, err := TOTPCodeAt(secret, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("unix=%d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Fatalf("unix=%d: got %s want %s", tc.unix, got, tc.want)
		}
	}
}

func TestValidateTOTPAcceptsSkewWindow(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := TOTPCodeAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTP(secret, code, now) {
		t.Fatal("current code must validate")
	}
	// previous and next step codes must also validate (±1 window)
	prev, _ := TOTPCodeAt(secret, now.Add(-30*time.Second))
	next, _ := TOTPCodeAt(secret, now.Add(30*time.Second))
	if !ValidateTOTP(secret, prev, now) || !ValidateTOTP(secret, next, now) {
		t.Fatal("±1 step codes must validate")
	}
	// two steps away must NOT validate
	far, _ := TOTPCodeAt(secret, now.Add(90*time.Second))
	if ValidateTOTP(secret, far, now) {
		t.Fatal("code two steps away must not validate")
	}
}

func TestValidateTOTPRejectsBadInput(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now().UTC()
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "  "} {
		if ValidateTOTP(secret, bad, now) {
			t.Fatalf("expected rejection for %q", bad)
		}
	}
	if ValidateTOTP("not-base32-!!!", "000000", now) {
		t.Fatal("invalid secret must not validate")
	}
}

func TestOTPAuthURIShape(t *testing.T) {
	uri := OTPAuthURI("Lattice", "alice", "JBSWY3DPEHPK3PXP")
	for _, want := range []string{"otpauth://totp/", "secret=JBSWY3DPEHPK3PXP", "issuer=Lattice", "digits=6", "period=30"} {
		if !contains(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
}

func TestGenerateRecoveryCodesAreHashable(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("want 10 codes, got %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatal("recovery codes must be unique")
		}
		seen[c] = true
		if _, err := HashSecret(c); err != nil {
			t.Fatalf("recovery code %q not hashable: %v", c, err)
		}
	}
}

func TestTOTPChallengeLifecycle(t *testing.T) {
	c, err := NewTOTPChallenge("user-1", "203.0.113.5", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if !c.Active(now) {
		t.Fatal("fresh challenge must be active")
	}
	c.Used = true
	if c.Active(now) {
		t.Fatal("used challenge must be inactive")
	}
	c.Used = false
	if c.Active(c.ExpiresAt.Add(time.Second)) {
		t.Fatal("expired challenge must be inactive")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
