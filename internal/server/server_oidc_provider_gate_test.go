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

// Whoever controls a provider's configuration controls what it asserts: an
// IdP that says a victim's email is verified binds that account on its first
// sign-in. So the changes that decide who can sign in (creating a provider,
// changing its issuer or client, widening its email domains) are made only
// from an interactive session, and with a fresh step-up when the operator
// has a second factor to give.

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

func TestOIDCProviderCreateNeedsStepUpFromAnOperatorWithASecondFactor(t *testing.T) {
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
	if meta["sign_in_change"] != "created" || meta["step_up"] != "true" {
		t.Fatalf("the create must be audited as a sign-in change made with step-up: %v", meta)
	}
}

func TestOIDCProviderCreateFromAnOperatorWithoutASecondFactor(t *testing.T) {
	// A fresh install whose operator has no second factor yet can still set
	// up single sign-on; the audit says no step-up was possible.
	_, st, h, cookie, csrf := gateFixture(t, false)
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", `{"issuer":"https://idp.acme.example","client_id":"cid","enabled":true}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" {
			if ev.Metadata["step_up"] != "no_second_factor" {
				t.Fatalf("the audit must say no step-up was possible: %v", ev.Metadata)
			}
			return
		}
	}
	t.Fatal("missing upsert audit")
}

func TestOIDCProviderIssuerClientAndDomainChangesNeedStepUp(t *testing.T) {
	srv, st, h, cookie, csrf := gateFixture(t, true)
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", DisplayName: "Google", Issuer: "https://accounts.google.com", ClientID: "cid",
		AllowedDomains: []string{"example.com", "example.org"}, Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	base := func(issuer, client, domains string) string {
		return `{"id":"g","display_name":"Google","issuer":"` + issuer + `","client_id":"` + client + `","allowed_domains":` + domains + `,"enabled":true`
	}
	for _, tc := range []struct{ name, body string }{
		{"repointing the issuer", base("https://idp.other.example", "cid", `["example.com","example.org"]`)},
		{"changing the client", base("https://accounts.google.com", "cid-2", `["example.com","example.org"]`)},
		{"adding a domain", base("https://accounts.google.com", "cid", `["example.com","example.org","evil.example"]`)},
		{"clearing the domains (any domain)", base("https://accounts.google.com", "cid", `[]`)},
	} {
		assertStepUpRefused(t, adminPOST(t, h, "/api/auth/oidc/providers", tc.body+`}`, cookie, csrf), tc.name)
	}
	if p, _ := st.OIDCProvider("g"); p.Issuer != "https://accounts.google.com" || p.ClientID != "cid" || len(p.AllowedDomains) != 2 {
		t.Fatalf("refused changes must store nothing: %+v", p)
	}

	// Narrowing the domains, renaming or disabling decides nothing new about
	// who can sign in, and needs no step-up.
	for _, body := range []string{
		base("https://accounts.google.com", "cid", `["example.com"]`) + `}`,
		`{"id":"g","display_name":"Google Workspace","issuer":"https://accounts.google.com","client_id":"cid","allowed_domains":["example.com"],"enabled":false}`,
	} {
		if rec := adminPOST(t, h, "/api/auth/oidc/providers", body, cookie, csrf); rec.Code != http.StatusOK {
			t.Fatalf("a change that grants nothing new: %d %s", rec.Code, rec.Body.String())
		}
	}

	// With a grant the repoint goes through.
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", base("https://idp.other.example", "cid", `["example.com"]`)+`,"step_up_grant":"`+adminStepUp(t, srv, st, cookie)+`"}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("repoint with a grant: %d %s", rec.Code, rec.Body.String())
	}
	if p, _ := st.OIDCProvider("g"); p.Issuer != "https://idp.other.example" {
		t.Fatalf("the repoint was not stored: %+v", p)
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
		"create":  `{"issuer":"https://idp.evil.example","client_id":"cid","enabled":true}`,
		"repoint": `{"id":"g","display_name":"Google","issuer":"https://idp.evil.example","client_id":"cid","enabled":true}`,
	} {
		res := doBearerJSON(t, h, http.MethodPost, "/api/auth/oidc/providers", body, token)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("a token's %s: got %d, want 403", name, res.StatusCode)
		}
	}
	if len(st.OIDCProviders()) != 1 {
		t.Fatalf("a token must not add a provider: %d", len(st.OIDCProviders()))
	}
	if p, _ := st.OIDCProvider("g"); p.Issuer != "https://accounts.google.com" {
		t.Fatalf("a token must not repoint a provider: %+v", p)
	}
	// A change that grants nothing new is still a token's to make.
	res := doBearerJSON(t, h, http.MethodPost, "/api/auth/oidc/providers", `{"id":"g","display_name":"Google Workspace","issuer":"https://accounts.google.com","client_id":"cid","enabled":true}`, token)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a token renaming a provider: got %d, want 200", res.StatusCode)
	}
}
