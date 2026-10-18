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

// A link's second-factor confirmation changes only a link that exists and
// still names the account, takes the issuer the sign-in saw, survives a
// restart together with the provider's skip_local_totp policy, and is
// cleared per provider without touching the link.
func TestOIDCIdentitySecondFactorConfirmationPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	c := testCipher(t)
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	const issuer = "https://accounts.google.com"
	if _, ok, err := s.ConfirmOIDCIdentitySecondFactor("g", issuer, "sub-1", "u1", at, 2); err != nil || ok {
		t.Fatalf("confirming a missing link must change nothing: ok=%v err=%v", ok, err)
	}
	if _, ok := s.OIDCIdentity("g", "sub-1"); ok {
		t.Fatal("confirmation must not create a link")
	}
	if err := s.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: issuer, ClientID: "cid", Enabled: true, SkipLocalTOTP: true, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: "https://old.example", Subject: "sub-1", UserID: "u1", CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "other", Issuer: "https://other.example", Subject: "sub-1", UserID: "u1", CreatedAt: at, SecondFactorAt: at, SecondFactorEpoch: 2}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ConfirmOIDCIdentitySecondFactor("g", issuer, "sub-1", "u2", at, 2); err != nil || ok {
		t.Fatalf("confirming for another account must change nothing: ok=%v err=%v", ok, err)
	}
	prior, ok, err := s.ConfirmOIDCIdentitySecondFactor("g", issuer, "sub-1", "u1", at, 2)
	if err != nil || !ok || !prior.SecondFactorAt.IsZero() || prior.Issuer != "https://old.example" {
		t.Fatalf("confirm: prior=%+v ok=%v err=%v", prior, ok, err)
	}

	s2, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.OIDCIdentity("g", "sub-1")
	if !ok || !got.SecondFactorAt.Equal(at) || got.SecondFactorEpoch != 2 || got.UserID != "u1" || got.Issuer != issuer {
		t.Fatalf("confirmation lost across a restart: %+v ok=%v", got, ok)
	}
	if p, ok := s2.OIDCProvider("g"); !ok || !p.SkipLocalTOTP {
		t.Fatalf("skip_local_totp lost across a restart: %+v ok=%v", p, ok)
	}

	if n, err := s2.ClearOIDCIdentityConfirmations("g"); err != nil || n != 1 {
		t.Fatalf("clear: n=%d err=%v", n, err)
	}
	if got, ok := s2.OIDCIdentity("g", "sub-1"); !ok || !got.SecondFactorAt.IsZero() || got.SecondFactorEpoch != 0 || got.UserID != "u1" {
		t.Fatalf("clearing must keep the link and drop only its confirmation: %+v ok=%v", got, ok)
	}
	if got, _ := s2.OIDCIdentity("other", "sub-1"); got.SecondFactorAt.IsZero() {
		t.Fatal("clearing one provider must not touch another's confirmations")
	}
	if n, err := s2.ClearOIDCIdentityConfirmations("g"); err != nil || n != 0 {
		t.Fatalf("a second clear has nothing to do: n=%d err=%v", n, err)
	}
}
