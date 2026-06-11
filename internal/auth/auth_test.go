package auth

import "testing"

func TestHashAndVerifySecret(t *testing.T) {
	hash, err := HashSecret("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySecret(hash, "correct horse battery staple") {
		t.Fatal("expected matching secret to verify")
	}
	if VerifySecret(hash, "wrong horse battery staple") {
		t.Fatal("expected wrong secret to fail")
	}
}

func TestHashSecretRejectsShortSecrets(t *testing.T) {
	if _, err := HashSecret("short"); err == nil {
		t.Fatal("expected short secret to fail")
	}
}
