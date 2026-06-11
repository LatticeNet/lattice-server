package auth

import "testing"

func TestFormatSplitRoundTrip(t *testing.T) {
	full := FormatToken("token_abc", "s3cr3t-value_X")
	id, secret, ok := SplitToken(full)
	if !ok {
		t.Fatal("expected split to succeed")
	}
	if id != "token_abc" || secret != "s3cr3t-value_X" {
		t.Fatalf("round trip mismatch: id=%q secret=%q", id, secret)
	}
}

func TestSplitTokenRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "noseparator", ".leadingdot", "trailingdot."} {
		if _, _, ok := SplitToken(bad); ok {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	// Must be safe to call repeatedly and never reports success for arbitrary input.
	DummyVerify("anything")
	DummyVerify("")
}

func TestHashVerifyRoundTrip(t *testing.T) {
	hash, err := HashSecret("a-strong-enough-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySecret(hash, "a-strong-enough-secret") {
		t.Fatal("correct secret should verify")
	}
	if VerifySecret(hash, "wrong") {
		t.Fatal("wrong secret must not verify")
	}
}

func TestHashRejectsShortSecret(t *testing.T) {
	if _, err := HashSecret("short"); err == nil {
		t.Fatal("expected short secret to be rejected")
	}
}
