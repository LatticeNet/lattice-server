package auth

import (
	"testing"
	"time"
)

func TestNewOIDCAuthState(t *testing.T) {
	a, err := NewOIDCAuthState("prov", "1.2.3.4", "/home", "verifier-xyz", "bind-token", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.State == "" || a.Nonce == "" {
		t.Fatal("state and nonce must be populated")
	}
	if a.State == a.Nonce {
		t.Fatal("state and nonce must differ")
	}
	if a.ProviderID != "prov" || a.ClientIP != "1.2.3.4" || a.RedirectAfter != "/home" || a.CodeVerifier != "verifier-xyz" {
		t.Fatalf("fields not set: %+v", a)
	}
	// Only the hash of the binding token is stored, and it matches the hash fn.
	if a.BindingHash != HashBindingToken("bind-token") {
		t.Fatal("binding hash mismatch")
	}
	if a.BindingHash == "bind-token" {
		t.Fatal("raw binding token must not be stored")
	}
	if HashBindingToken("a") == HashBindingToken("b") {
		t.Fatal("distinct tokens must hash differently")
	}
	if a.Expired() {
		t.Fatal("freshly minted state should not be expired")
	}
}

func TestOIDCAuthStateUniqueAndExpiry(t *testing.T) {
	seen := map[string]bool{}
	for range 500 {
		a, err := NewOIDCAuthState("p", "ip", "/", "v", "b", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if seen[a.State] {
			t.Fatal("duplicate state value")
		}
		seen[a.State] = true
	}
	past, err := NewOIDCAuthState("p", "ip", "/", "v", "b", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !past.Expired() {
		t.Fatal("negative-ttl state should be expired")
	}
}
