package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// An identity link names a subject at one issuer. Subjects are unique only
// per issuer, so a link answers only for the issuer it was created under: a
// provider repointed at another issuer, whoever controls that issuer, cannot
// present a linked subject and sign in as the linked account.

// linkIssuerFixture is a provider "g" pointed at the mock IdP, with a link
// recorded for the IdP's subject under linkIssuer.
func linkIssuerFixture(t *testing.T, linkIssuer string, user model.User) (*mockIDP, *store.Store, http.Handler) {
	t.Helper()
	idp := newMockIDP(t)
	idp.sub = "sub-linked"
	idp.email = "attacker@repointed.example"
	idp.emailVerified = true
	srv, st := newOIDCServer(t, idp.server.Client())
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", DisplayName: "Google", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUser(user); err != nil {
		t.Fatal(err)
	}
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: linkIssuer, Subject: "sub-linked", UserID: user.ID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return idp, st, srv.Handler()
}

func ssoOnce(t *testing.T, h http.Handler, idp *mockIDP) *http.Response {
	t.Helper()
	state, nonce, bind := startAndParse(t, h, "g")
	idp.nonce = nonce
	return oidcCallback(h, state, "xyz", bind).Result()
}

func TestOIDCLinkFromAnotherIssuerDoesNotSignIn(t *testing.T) {
	// The account was linked while "g" pointed at Google; someone holding
	// oidc:admin has since pointed "g" at an IdP they run, which presents the
	// linked subject. The account has no TOTP and its username is not an
	// email, so nothing but the link could let this sign-in through.
	idp, st, h := linkIssuerFixture(t, "https://accounts.google.com", model.User{ID: "u-victim", Username: "victim", Scopes: []string{"*"}})
	res := ssoOnce(t, h, idp)
	if hasSessionCookie(res.Cookies()) {
		t.Fatal("a link recorded under another issuer signed the account in")
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "sso_error=denied") {
		t.Fatalf("expected sso_error=denied, got %s", loc)
	}
	var ignored *model.AuditEvent
	for _, ev := range st.AuditEvents() {
		if ev.Action == "login.oidc.stale_link_ignored" {
			ev := ev
			ignored = &ev
		}
	}
	if ignored == nil || ignored.Metadata["link_issuer"] != "https://accounts.google.com" || ignored.Metadata["provider_issuer"] != idp.server.URL || ignored.ActorID != "u-victim" {
		t.Fatalf("the ignored link must be audited with both issuers and the linked account: %+v", ignored)
	}
	if strings.Contains(ignored.Metadata["subject"], "sub-linked") {
		t.Fatalf("the audit must mask the subject: %q", ignored.Metadata["subject"])
	}
}

func TestOIDCLinkUnderTheCurrentIssuerStillSignsIn(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-linked"
	_, st, h := func() (*mockIDP, *store.Store, http.Handler) {
		srv, st := newOIDCServer(t, idp.server.Client())
		return idp, st, srv.Handler()
	}()
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUser(model.User{ID: "u-ops", Username: "ops"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: idp.server.URL, Subject: "sub-linked", UserID: "u-ops", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if res := ssoOnce(t, h, idp); !hasSessionCookie(res.Cookies()) {
		t.Fatalf("a link under the provider's own issuer must keep signing in: %s", res.Header.Get("Location"))
	}
}

func TestOIDCStaleLinkIsReplacedByTheFirstSignInRule(t *testing.T) {
	// Under the new issuer the same subject string is a different identity,
	// so the sign-in is judged as a first one: a verified email naming a
	// local account binds a fresh link under the current issuer, unconfirmed.
	idp, st, h := linkIssuerFixture(t, "https://accounts.google.com", model.User{ID: "u-alice", Username: "alice@example.com"})
	idp.email = "alice@example.com"
	old, _ := st.OIDCIdentity("g", "sub-linked")
	old.SecondFactorAt, old.SecondFactorEpoch = time.Now().UTC(), 0
	if err := st.PutOIDCIdentity(old); err != nil {
		t.Fatal(err)
	}
	if res := ssoOnce(t, h, idp); !hasSessionCookie(res.Cookies()) {
		t.Fatalf("a verified email naming the account binds as on a first sign-in: %s", res.Header.Get("Location"))
	}
	link, ok := st.OIDCIdentity("g", "sub-linked")
	if !ok || link.Issuer != idp.server.URL || !link.SecondFactorAt.IsZero() {
		t.Fatalf("the stale link must be replaced by one under the current issuer, unconfirmed: %+v ok=%v", link, ok)
	}
}

func TestOIDCIssuerChangeRemovesTheOldIssuersLinks(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	const oldIssuer, newIssuer = "https://idp.old.example", "https://idp.new.example"
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: oldIssuer, ClientID: "cid", Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for _, idn := range []model.OIDCIdentity{
		{ProviderID: "g", Issuer: oldIssuer, Subject: "s1", UserID: "u1"},
		{ProviderID: "g", Issuer: oldIssuer, Subject: "s2", UserID: "u2"},
		{ProviderID: "other", Issuer: oldIssuer, Subject: "s1", UserID: "u1"},
	} {
		idn.CreatedAt = time.Now().UTC()
		if err := st.PutOIDCIdentity(idn); err != nil {
			t.Fatal(err)
		}
	}
	cookie, csrf := adminLogin(t, h)
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", `{"id":"g","issuer":"`+newIssuer+`","client_id":"cid","enabled":true}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("repoint: %d %s", rec.Code, rec.Body.String())
	}
	for _, sub := range []string{"s1", "s2"} {
		if _, ok := st.OIDCIdentity("g", sub); ok {
			t.Fatalf("link %s under the old issuer survived the repoint", sub)
		}
	}
	if _, ok := st.OIDCIdentity("other", "s1"); !ok {
		t.Fatal("another provider's link must not be touched")
	}
	var meta map[string]string
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" && ev.Metadata["provider"] == "g" {
			meta = ev.Metadata
			break // newest first
		}
	}
	if meta["links_removed"] != "2" || meta["old_issuer"] != oldIssuer || meta["issuer"] != newIssuer {
		t.Fatalf("the repoint must be audited with the old issuer and the links it removed: %v", meta)
	}

	// Saving again under the same issuer removes nothing and says nothing.
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: newIssuer, Subject: "s3", UserID: "u3", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", `{"id":"g","issuer":"`+newIssuer+`","client_id":"cid","enabled":true}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("resave: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := st.OIDCIdentity("g", "s3"); !ok {
		t.Fatal("a link under the current issuer must survive a save")
	}
}
