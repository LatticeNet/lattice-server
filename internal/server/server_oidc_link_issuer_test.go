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
	// The presenter is unknown: the event names no actor, and the account the
	// link names sits in the metadata, so nobody reads the victim as the actor.
	if ignored == nil || ignored.Metadata["link_issuer"] != "https://accounts.google.com" || ignored.Metadata["provider_issuer"] != idp.server.URL ||
		ignored.Metadata["linked_user"] != "u-victim" || ignored.ActorID != "" {
		t.Fatalf("the ignored link must be audited with both issuers and the linked account: %+v", ignored)
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action == "login.oidc" && ev.Decision == "deny" && (strings.Contains(ev.Metadata["sub"], "sub-linked") || strings.Contains(ev.Metadata["email"], "attacker@") || strings.Contains(ev.Reason, "attacker@")) {
			t.Fatalf("the deny audit must mask what the provider asserted: %+v", ev)
		}
	}
	if strings.Contains(ignored.Metadata["subject"], "sub-linked") {
		t.Fatalf("the audit must mask the subject: %q", ignored.Metadata["subject"])
	}
}

func TestOIDCLinkUnderTheCurrentIssuerStillSignsIn(t *testing.T) {
	idp, st, h := linkIssuerFixture(t, "", model.User{ID: "u-ops", Username: "ops"})
	link, _ := st.OIDCIdentity("g", "sub-linked")
	link.Issuer = idp.server.URL
	if err := st.PutOIDCIdentity(link); err != nil {
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
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", `{"id":"g","issuer":"`+newIssuer+`","client_id":"cid","enabled":true,"step_up_grant":"`+adminStepUp(t, srv, st, cookie)+`"}`, cookie, csrf); rec.Code != http.StatusOK {
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

func TestOIDCProviderRepointedDuringTheExchangeAdmitsNobody(t *testing.T) {
	// The link is under the issuer the claims are verified against, and the
	// account's username is the verified email, so either path would admit
	// it. The operator repoints, disables or re-clients the provider while
	// the exchange is in flight, because that IdP is compromised. Nothing is
	// admitted on the strength of the old record: no session, no challenge,
	// and no link written under the issuer the provider left.
	for name, change := range map[string]func(p *model.OIDCProvider){
		"repointed":  func(p *model.OIDCProvider) { p.Issuer = "https://idp.replacement.example" },
		"disabled":   func(p *model.OIDCProvider) { p.Enabled = false },
		"new client": func(p *model.OIDCProvider) { p.ClientID = "another-client" },
	} {
		t.Run(name, func(t *testing.T) {
			idp, st, h := linkIssuerFixture(t, "", model.User{ID: "u-ops", Username: "ops@example.com"})
			idp.email = "ops@example.com"
			link, _ := st.OIDCIdentity("g", "sub-linked")
			link.Issuer = idp.server.URL
			if err := st.PutOIDCIdentity(link); err != nil {
				t.Fatal(err)
			}
			idp.onToken = func() {
				p, _ := st.OIDCProvider("g")
				change(&p)
				if err := st.UpsertOIDCProvider(p); err != nil {
					t.Error(err)
				}
			}
			res := ssoOnce(t, h, idp)
			if hasSessionCookie(res.Cookies()) || !strings.Contains(res.Header.Get("Location"), "sso_error=unavailable") {
				t.Fatalf("a provider changed during the exchange must admit nobody: %s", res.Header.Get("Location"))
			}
			if p, _ := st.OIDCProvider("g"); p.Issuer != idp.server.URL {
				if _, ok := st.OIDCIdentity("g", "sub-linked"); ok {
					t.Fatal("no link may be written under the issuer the provider left")
				}
			}
		})
	}
}

func TestOIDCStaleConfirmedLinkDoesNotSkipTheCode(t *testing.T) {
	// A link confirmed for skip_local_totp under the old issuer: the new
	// issuer's sign-in rebinds by email (a fresh, unconfirmed link), so the
	// account's code is asked even though the policy is on.
	idp, st, h := linkIssuerFixture(t, "https://accounts.google.com", model.User{ID: "u-2fa", Username: "twofa@example.com", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"})
	idp.email = "twofa@example.com"
	p, _ := st.OIDCProvider("g")
	p.SkipLocalTOTP = true
	if err := st.UpsertOIDCProvider(p); err != nil {
		t.Fatal(err)
	}
	// The settle above removed the old-issuer link; put it back as a link a
	// flip-back or a race could have left behind, confirmed.
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: "https://accounts.google.com", Subject: "sub-linked", UserID: "u-2fa",
		CreatedAt: time.Now().UTC(), SecondFactorAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	res := ssoOnce(t, h, idp)
	if hasSessionCookie(res.Cookies()) || !strings.Contains(res.Header.Get("Location"), "totp_challenge=") {
		t.Fatalf("a stale confirmation must not skip the code: %s", res.Header.Get("Location"))
	}
	if link, _ := st.OIDCIdentity("g", "sub-linked"); link.Issuer != idp.server.URL || !link.SecondFactorAt.IsZero() {
		t.Fatalf("the rebind must be under the current issuer and unconfirmed: %+v", link)
	}
}

func TestOIDCRepointAndPolicyOnInOneSaveReportBoth(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	const oldIssuer, newIssuer = "https://idp.old.example", "https://idp.new.example"
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: oldIssuer, ClientID: "cid", Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: oldIssuer, Subject: "s1", UserID: "u1", CreatedAt: time.Now().UTC(), SecondFactorAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := adminLogin(t, h)
	body := `{"id":"g","issuer":"` + newIssuer + `","client_id":"cid","enabled":true,"skip_local_totp":true,"step_up_grant":"` + adminStepUp(t, srv, st, cookie) + `"}`
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", body, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("repoint and turn on: %d %s", rec.Code, rec.Body.String())
	}
	var meta map[string]string
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" {
			meta = ev.Metadata
			break
		}
	}
	if meta["links_removed"] != "1" || meta["confirmations_cleared"] != "0" || meta["old_issuer"] != oldIssuer || meta["new_skip_local_totp"] != "true" {
		t.Fatalf("one save that repoints and turns the policy on must report both: %v", meta)
	}
}

func TestOIDCProviderRecreatedUnderAnotherIssuerFindsNoLinks(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: "https://idp.old.example", ClientID: "cid", Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "g", Issuer: "https://idp.old.example", Subject: "s1", UserID: "u1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := adminLogin(t, h)
	if rec := adminPOST(t, h, "/api/auth/oidc/providers/delete", `{"id":"g"}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := st.OIDCIdentity("g", "s1"); !ok {
		t.Fatal("deleting a provider keeps its links (a re-created provider under the same issuer finds them)")
	}
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", `{"id":"g","issuer":"https://idp.new.example","client_id":"cid","enabled":true,"step_up_grant":"`+adminStepUp(t, srv, st, cookie)+`"}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("re-create: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := st.OIDCIdentity("g", "s1"); ok {
		t.Fatal("a provider re-created under another issuer must not find the old issuer's links")
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" {
			if ev.Metadata["links_removed"] != "1" {
				t.Fatalf("the re-create must report the links it removed: %v", ev.Metadata)
			}
			break
		}
	}
}
