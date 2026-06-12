package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
)

func TestOIDCProviderCRUDAndSecretAtRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	c := testCipher(t)

	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "super-secret-oauth-client-value"
	p := model.OIDCProvider{
		ID: "g", DisplayName: "Google", Issuer: "https://accounts.google.com",
		ClientID: "client-123", ClientSecret: secret, Enabled: true,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.UpsertOIDCProvider(p); err != nil {
		t.Fatal(err)
	}

	// Secret must not be plaintext on disk.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), secret) {
		t.Fatal("oidc client secret leaked to disk in plaintext")
	}
	if !strings.Contains(string(raw), "client-123") {
		t.Fatal("non-secret client_id should be readable on disk")
	}

	// Reopen decrypts.
	s2, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.OIDCProvider("g")
	if !ok || got.ClientSecret != secret {
		t.Fatalf("secret not recovered: %q ok=%v", got.ClientSecret, ok)
	}
	if len(s2.EnabledOIDCProviders()) != 1 {
		t.Fatal("expected one enabled provider")
	}

	// Disable → not in enabled list.
	got.Enabled = false
	if err := s2.UpsertOIDCProvider(got); err != nil {
		t.Fatal(err)
	}
	if len(s2.EnabledOIDCProviders()) != 0 {
		t.Fatal("disabled provider should be excluded from enabled list")
	}
	if err := s2.DeleteOIDCProvider("g"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.OIDCProvider("g"); ok {
		t.Fatal("provider should be deleted")
	}
}

func TestOIDCIdentityLink(t *testing.T) {
	s, _ := OpenWithCipher("", nil)
	idn := model.OIDCIdentity{ProviderID: "prov-a", Issuer: "https://idp", Subject: "sub-1", UserID: "u1", Email: "a@b.com", CreatedAt: time.Now().UTC()}
	if err := s.PutOIDCIdentity(idn); err != nil {
		t.Fatal(err)
	}
	got, ok := s.OIDCIdentity("prov-a", "sub-1")
	if !ok || got.UserID != "u1" {
		t.Fatalf("identity not found: %+v ok=%v", got, ok)
	}
	if _, ok := s.OIDCIdentity("prov-a", "other"); ok {
		t.Fatal("unknown subject should not resolve")
	}
	// ProviderID is the key (the vetted record), not the issuer string — a
	// different provider that happens to share an issuer/subject is distinct.
	if _, ok := s.OIDCIdentity("prov-b", "sub-1"); ok {
		t.Fatal("provider id must be part of the identity key")
	}
}

func TestOIDCAuthStateSingleUseAndExpiry(t *testing.T) {
	s, _ := OpenWithCipher("", nil)
	st, _ := auth.NewOIDCAuthState("p", "1.2.3.4", "/", "verifier", "bind", 10*time.Minute)
	if err := s.PutOIDCAuthState(st); err != nil {
		t.Fatal(err)
	}
	// First consume succeeds.
	got, ok := s.ConsumeOIDCAuthState(st.State)
	if !ok || got.Nonce != st.Nonce {
		t.Fatalf("first consume failed: %+v ok=%v", got, ok)
	}
	// Second consume of the same state fails (single use).
	if _, ok := s.ConsumeOIDCAuthState(st.State); ok {
		t.Fatal("auth state must be single-use")
	}

	// Expired state: consume returns false (and removes it).
	expired, _ := auth.NewOIDCAuthState("p", "ip", "/", "v", "b", -time.Second)
	if err := s.PutOIDCAuthState(expired); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ConsumeOIDCAuthState(expired.State); ok {
		t.Fatal("expired state should not consume")
	}
}
