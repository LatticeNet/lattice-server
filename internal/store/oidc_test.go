package store

import (
	"errors"
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

// A link's second-factor confirmation changes only a link that exists, still
// names the account and was recorded under the issuer the sign-in saw; it
// survives a restart together with the provider's skip_local_totp policy, and
// is cleared per provider without touching the link.
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
	if _, ok, err := s.ConfirmOIDCIdentitySecondFactor("g", issuer, "sub-1", "u1", at, 2); err != nil || ok {
		t.Fatalf("a link recorded under another issuer must not be confirmed under this one: ok=%v err=%v", ok, err)
	}
	if got, _ := s.OIDCIdentity("g", "sub-1"); got.Issuer != "https://old.example" || !got.SecondFactorAt.IsZero() {
		t.Fatalf("a refused confirmation must leave the link as it was: %+v", got)
	}
	if err := s.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: issuer, Subject: "sub-1", UserID: "u1", CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "other", Issuer: "https://other.example", Subject: "sub-1", UserID: "u1", CreatedAt: at, SecondFactorAt: at, SecondFactorEpoch: 2}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ConfirmOIDCIdentitySecondFactor("g", issuer, "sub-1", "u2", at, 2); err != nil || ok {
		t.Fatalf("confirming for another account must change nothing: ok=%v err=%v", ok, err)
	}
	prior, ok, err := s.ConfirmOIDCIdentitySecondFactor("g", issuer, "sub-1", "u1", at, 2)
	if err != nil || !ok || !prior.SecondFactorAt.IsZero() || prior.Issuer != issuer {
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

// Turning the policy on stores the provider and clears its links'
// confirmations in one write, and the provider's client secret stays
// encrypted at rest on that path too.
func TestUpsertOIDCProviderSettlingLinksClearsConfirmations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	c := testCipher(t)
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	const secret = "super-secret-oauth-client-value"
	p := model.OIDCProvider{ID: "g", Issuer: "https://accounts.google.com", ClientID: "cid", ClientSecret: secret, Enabled: true, CreatedAt: at}
	if err := s.UpsertOIDCProvider(p); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"sub-1", "sub-2"} {
		if err := s.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: p.Issuer, Subject: sub, UserID: "u1", CreatedAt: at, SecondFactorAt: at, SecondFactorEpoch: 1}); err != nil {
			t.Fatal(err)
		}
	}
	p.SkipLocalTOTP = true
	changes, committed, err := s.UpsertOIDCProviderSettlingLinks(p, true, nil)
	if err != nil || !committed || changes.ConfirmationsCleared != 2 || changes.LinksRemoved != 0 {
		t.Fatalf("upsert clearing: changes=%+v committed=%v err=%v", changes, committed, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), secret) {
		t.Fatal("oidc client secret leaked to disk in plaintext")
	}
	s2, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.OIDCProvider("g")
	if !ok || !got.SkipLocalTOTP || got.ClientSecret != secret {
		t.Fatalf("provider after restart: skip=%v secret recovered=%v ok=%v", got.SkipLocalTOTP, got.ClientSecret == secret, ok)
	}
	for _, sub := range []string{"sub-1", "sub-2"} {
		if idn, _ := s2.OIDCIdentity("g", sub); !idn.SecondFactorAt.IsZero() || idn.SecondFactorEpoch != 0 {
			t.Fatalf("%s kept its confirmation: %+v", sub, idn)
		}
	}
}

// Saving a provider removes its links recorded under any other issuer, in the
// same write, keeps the links under its own issuer and leaves other providers'
// links alone; the result survives a restart.
func TestUpsertOIDCProviderSettlingLinksRemovesOtherIssuers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	c := testCipher(t)
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	for _, idn := range []model.OIDCIdentity{
		{ProviderID: "g", Issuer: "https://old.example", Subject: "s1", UserID: "u1"},
		{ProviderID: "g", Issuer: "", Subject: "s2", UserID: "u2"},
		{ProviderID: "g", Issuer: "https://new.example", Subject: "s3", UserID: "u3", SecondFactorAt: at},
		{ProviderID: "other", Issuer: "https://old.example", Subject: "s1", UserID: "u1"},
	} {
		idn.CreatedAt = at
		if err := s.PutOIDCIdentity(idn); err != nil {
			t.Fatal(err)
		}
	}
	changes, committed, err := s.UpsertOIDCProviderSettlingLinks(model.OIDCProvider{ID: "g", Issuer: "https://new.example", ClientID: "cid", Enabled: true, CreatedAt: at}, false, nil)
	if err != nil || !committed || changes.LinksRemoved != 2 || changes.ConfirmationsCleared != 0 {
		t.Fatalf("settle: changes=%+v committed=%v err=%v", changes, committed, err)
	}
	s2, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"s1", "s2"} {
		if _, ok := s2.OIDCIdentity("g", sub); ok {
			t.Fatalf("link %s from another issuer survived", sub)
		}
	}
	if idn, ok := s2.OIDCIdentity("g", "s3"); !ok || idn.SecondFactorAt.IsZero() {
		t.Fatalf("the link under the provider's issuer must stay, confirmation and all: %+v ok=%v", idn, ok)
	}
	if _, ok := s2.OIDCIdentity("other", "s1"); !ok {
		t.Fatal("another provider's link must not be touched")
	}
	if p, ok := s2.OIDCProvider("g"); !ok || p.Issuer != "https://new.example" {
		t.Fatalf("provider after restart: %+v ok=%v", p, ok)
	}
}

// A guard sees the record about to be replaced under the store lock, and its
// refusal leaves the provider and its links as they were.
func TestUpsertOIDCProviderSettlingLinksGuard(t *testing.T) {
	s, _ := OpenWithCipher("", nil)
	at := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	if err := s.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: "https://old.example", ClientID: "cid", Enabled: true, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: "https://old.example", Subject: "s1", UserID: "u1", CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("changed meanwhile")
	var seen *model.OIDCProvider
	_, committed, err := s.UpsertOIDCProviderSettlingLinks(model.OIDCProvider{ID: "g", Issuer: "https://new.example", ClientID: "cid", Enabled: true, CreatedAt: at}, false,
		func(current *model.OIDCProvider) error { seen = current; return refused })
	if !errors.Is(err, refused) || committed {
		t.Fatalf("a guard refusal must refuse the write: committed=%v err=%v", committed, err)
	}
	if seen == nil || seen.Issuer != "https://old.example" {
		t.Fatalf("the guard must see the record about to be replaced: %+v", seen)
	}
	if p, _ := s.OIDCProvider("g"); p.Issuer != "https://old.example" {
		t.Fatalf("a refused write must leave the provider: %+v", p)
	}
	if _, ok := s.OIDCIdentity("g", "s1"); !ok {
		t.Fatal("a refused write must leave the links")
	}
	var created *model.OIDCProvider = &model.OIDCProvider{}
	if _, committed, err := s.UpsertOIDCProviderSettlingLinks(model.OIDCProvider{ID: "new", Issuer: "https://x.example", ClientID: "c", CreatedAt: at}, false,
		func(current *model.OIDCProvider) error { created = current; return nil }); err != nil || !committed || created != nil {
		t.Fatalf("a new provider's guard sees nil and the write goes through: committed=%v err=%v current=%+v", committed, err, created)
	}
}
