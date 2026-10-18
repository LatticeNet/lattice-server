package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Whoever controls which IdP a provider trusts controls what it asserts: an
// IdP that says a victim's email is verified binds that account on its first
// sign-in. So creating a provider and changing its issuer or client are made
// only from an interactive session with a fresh step-up; a token never makes
// them, so agents cannot add or repoint an IdP.

func gateFixture(t *testing.T, adminTOTP bool) (*Server, *store.Store, http.Handler, string, string) {
	t.Helper()
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	cookie, csrf := adminLogin(t, h)
	if adminTOTP {
		admin, _ := st.UserByUsername("admin")
		admin.TOTPEnabled, admin.TOTPSecret = true, "JBSWY3DPEHPK3PXP"
		if err := st.UpsertUser(admin); err != nil {
			t.Fatal(err)
		}
	}
	return srv, st, h, cookie, csrf
}

func assertStepUpRefused(t *testing.T, rec interface {
	Result() *http.Response
}, what string) {
	t.Helper()
	res := rec.Result()
	defer res.Body.Close()
	var body model.APIErrorResponse
	if res.StatusCode != http.StatusForbidden || json.NewDecoder(res.Body).Decode(&body) != nil || body.Error.Code != apiErrorStepUpRequired {
		t.Fatalf("%s without step-up: got %d %+v, want 403 %s", what, res.StatusCode, body, apiErrorStepUpRequired)
	}
}

func TestOIDCProviderCreateNeedsStepUp(t *testing.T) {
	srv, st, h, cookie, csrf := gateFixture(t, true)
	var sent []string
	srv.emitNotify = func(title, body string) { sent = append(sent, title+": "+body) }
	const create = `{"display_name":"Acme","issuer":"https://idp.acme.example","client_id":"cid","enabled":true`
	assertStepUpRefused(t, adminPOST(t, h, "/api/auth/oidc/providers", create+`}`, cookie, csrf), "creating a provider")
	if len(st.OIDCProviders()) != 0 {
		t.Fatal("a refused create must store nothing")
	}
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", create+`,"step_up_grant":"`+adminStepUp(t, srv, st, cookie)+`"}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("create with a grant: %d %s", rec.Code, rec.Body.String())
	}
	if len(sent) != 1 || !strings.Contains(sent[0], "https://idp.acme.example") {
		t.Fatalf("adding a provider must be notified with its issuer: %q", sent)
	}
	var meta map[string]string
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" {
			meta = ev.Metadata
			break
		}
	}
	if meta["sign_in_change"] != "created" || meta["new_issuer"] != "https://idp.acme.example" || meta["new_client_id"] != "cid" {
		t.Fatalf("the create must be audited with the new issuer and client: %v", meta)
	}
}

func TestOIDCProviderCreateNeedsASecondFactorToStepUpWith(t *testing.T) {
	// No exemption: an operator with no second factor enrolls one first.
	_, st, h, cookie, csrf := gateFixture(t, false)
	rec := adminPOST(t, h, "/api/auth/oidc/providers", `{"issuer":"https://idp.acme.example","client_id":"cid","enabled":true}`, cookie, csrf)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "enroll an authenticator app or a passkey first") {
		t.Fatalf("an operator with no second factor: got %d %s", rec.Code, rec.Body.String())
	}
	if len(st.OIDCProviders()) != 0 {
		t.Fatal("a refused create must store nothing")
	}
}

func TestOIDCProviderIssuerAndClientChangesNeedStepUp(t *testing.T) {
	srv, st, h, cookie, csrf := gateFixture(t, true)
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", DisplayName: "Google", Issuer: "https://accounts.google.com", ClientID: "cid",
		AllowedDomains: []string{"example.com", "example.org"}, Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	srv.emitNotify = func(title, body string) { sent = append(sent, title) }
	base := func(issuer, client, domains string) string {
		return `{"id":"g","display_name":"Google","issuer":"` + issuer + `","client_id":"` + client + `","allowed_domains":` + domains + `,"enabled":true`
	}
	for _, tc := range []struct{ name, body string }{
		{"repointing the issuer", base("https://idp.other.example", "cid", `["example.com","example.org"]`)},
		{"changing the client", base("https://accounts.google.com", "cid-2", `["example.com","example.org"]`)},
	} {
		assertStepUpRefused(t, adminPOST(t, h, "/api/auth/oidc/providers", tc.body+`}`, cookie, csrf), tc.name)
	}
	if p, _ := st.OIDCProvider("g"); p.Issuer != "https://accounts.google.com" || p.ClientID != "cid" {
		t.Fatalf("refused changes must store nothing: %+v", p)
	}

	// The email domains, the name and the enabled flag leave the asserting
	// IdP as it is, and need no step-up: widening, narrowing, clearing,
	// renaming, disabling and re-enabling.
	for _, body := range []string{
		base("https://accounts.google.com", "cid", `["example.com","example.org","example.net"]`) + `}`,
		base("https://accounts.google.com", "cid", `["example.com"]`) + `}`,
		base("https://accounts.google.com", "cid", `[]`) + `}`,
		`{"id":"g","display_name":"Google Workspace","issuer":"https://accounts.google.com","client_id":"cid","enabled":false}`,
		`{"id":"g","display_name":"Google Workspace","issuer":"https://accounts.google.com","client_id":"cid","enabled":true}`,
	} {
		if rec := adminPOST(t, h, "/api/auth/oidc/providers", body, cookie, csrf); rec.Code != http.StatusOK {
			t.Fatalf("a change that leaves the IdP as it is: %d %s", rec.Code, rec.Body.String())
		}
	}
	if len(sent) != 0 {
		t.Fatalf("changes that leave the IdP as it is are not notified: %q", sent)
	}

	// With a grant the repoint goes through, audited with old and new values.
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", base("https://idp.other.example", "cid-2", `[]`)+`,"step_up_grant":"`+adminStepUp(t, srv, st, cookie)+`"}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("repoint with a grant: %d %s", rec.Code, rec.Body.String())
	}
	var meta map[string]string
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" {
			meta = ev.Metadata
			break
		}
	}
	if meta["sign_in_change"] != "repointed" || meta["old_issuer"] != "https://accounts.google.com" || meta["new_issuer"] != "https://idp.other.example" ||
		meta["old_client_id"] != "cid" || meta["new_client_id"] != "cid-2" {
		t.Fatalf("the repoint must be audited with old and new issuer and client: %v", meta)
	}
	if len(sent) != 1 || sent[0] != "Identity provider repointed" {
		t.Fatalf("the repoint must be notified: %q", sent)
	}
}

func TestOIDCProviderSignInChangesAreRefusedToTokens(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	cookies, csrf := loginSession(t, h)
	token := createPAT(t, h, cookies, csrf, []string{"oidc:admin"}, nil)
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", DisplayName: "Google", Issuer: "https://accounts.google.com", ClientID: "cid", Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"create":  `{"issuer":"https://idp.evil.example","client_id":"cid","enabled":true,"step_up_grant":"anything"}`,
		"repoint": `{"id":"g","display_name":"Google","issuer":"https://idp.evil.example","client_id":"cid","enabled":true}`,
		"client":  `{"id":"g","display_name":"Google","issuer":"https://accounts.google.com","client_id":"evil","enabled":true}`,
	} {
		res := doBearerJSON(t, h, http.MethodPost, "/api/auth/oidc/providers", body, token)
		var refused model.APIErrorResponse
		_ = json.NewDecoder(res.Body).Decode(&refused)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden || refused.Error.Code != apiErrorStepUpRequired {
			t.Fatalf("a token's %s: got %d %+v, want 403 %s", name, res.StatusCode, refused, apiErrorStepUpRequired)
		}
	}
	if len(st.OIDCProviders()) != 1 {
		t.Fatalf("a token must not add a provider: %d", len(st.OIDCProviders()))
	}
	if p, _ := st.OIDCProvider("g"); p.Issuer != "https://accounts.google.com" || p.ClientID != "cid" {
		t.Fatalf("a token must not repoint a provider: %+v", p)
	}
	// A change that leaves the IdP as it is stays a token's to make.
	res := doBearerJSON(t, h, http.MethodPost, "/api/auth/oidc/providers", `{"id":"g","display_name":"Google Workspace","issuer":"https://accounts.google.com","client_id":"cid","allowed_domains":["example.com"],"enabled":true}`, token)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a token renaming a provider: got %d, want 200", res.StatusCode)
	}
}

func TestOIDCFirstSignInLinkIsAuditedAndNotified(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub, idp.email, idp.emailVerified = "sub-new", "ops@example.com", true
	srv, st := newOIDCServer(t, idp.server.Client())
	h := srv.Handler()
	var sent []string
	srv.emitNotify = func(title, body string) { sent = append(sent, title+": "+body) }
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", DisplayName: "Google", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUser(model.User{ID: "u-ops", Username: "ops@example.com"}); err != nil {
		t.Fatal(err)
	}
	state, nonce, bind := startAndParse(t, h, "g")
	idp.nonce = nonce
	if rec := oidcCallback(h, state, "xyz", bind); !hasSessionCookie(rec.Result().Cookies()) {
		t.Fatalf("first sign-in: %s", rec.Header().Get("Location"))
	}
	if len(sent) != 1 || !strings.Contains(sent[0], "linked to ops@example.com") || strings.Contains(sent[0], "sub-new") || !strings.Contains(sent[0], "no second factor") {
		t.Fatalf("a first sign-in link must be notified, naming the account, masking the subject and saying it has no second factor: %q", sent)
	}
	found := false
	for _, ev := range st.AuditEvents() {
		if ev.Action == "login.oidc.linked" && ev.ActorID == "u-ops" && ev.Metadata["totp_enabled"] == "false" && ev.Metadata["subject"] == maskSSOSubject("sub-new") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing login.oidc.linked audit: %+v", st.AuditEvents())
	}
	// A returning sign-in through the link says nothing new.
	sent = nil
	state, nonce, bind = startAndParse(t, h, "g")
	idp.nonce = nonce
	oidcCallback(h, state, "xyz", bind)
	if len(sent) != 0 {
		t.Fatalf("a returning sign-in must not notify: %q", sent)
	}
}
