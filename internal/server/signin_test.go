package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A server that terminates TLS itself knows the browser reached it over
// HTTPS, so its sign-in cookies carry Secure without -secure-cookies. Over
// plain HTTP, where a TLS proxy may or may not sit in front, Secure still
// follows the flag.
func TestSessionCookieIsSecureOverDirectTLS(t *testing.T) {
	h, _ := newTestServer(t)
	for i, tc := range []struct {
		name string
		tls  bool
		want bool
	}{{"direct TLS", true, true}, {"plain HTTP", false, false}} {
		req := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"username":"admin","password":"`+testAdminPass+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100." + string(rune('1'+i)) + ":4000"
		if tc.tls {
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		c := cookieNamed(rec, "lattice_session")
		if c == nil {
			t.Fatalf("%s: no session cookie; status %d, body %s", tc.name, rec.Code, rec.Body.String())
		}
		if c.Secure != tc.want {
			t.Errorf("%s: session cookie Secure = %t, want %t", tc.name, c.Secure, tc.want)
		}
	}
}

func TestOIDCBindingCookieIsSecureOverDirectTLS(t *testing.T) {
	idp := newMockIDP(t)
	srv, st := newOIDCServer(t, idp.server.Client())
	h := srv.Handler()
	if err := st.UpsertOIDCProvider(model.OIDCProvider{
		ID: "g", DisplayName: "Test", Issuer: idp.server.URL, ClientID: idp.clientID,
		ClientSecret: "s", AllowedDomains: []string{"example.com"}, Enabled: true,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?provider=g", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: got %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	c := cookieNamed(rec, oidcBindingCookie)
	if c == nil {
		t.Fatal("start set no binding cookie")
	}
	if !c.Secure {
		t.Error("binding cookie set over direct TLS lacks Secure")
	}
}

// A browser drops a tab from a URL before it parses it, so a landing path of
// "/<tab>/host" would send a freshly signed-in user to another origin. The
// whole flow, start to callback, must land on this origin.
func TestOIDCCallbackRedirectStaysOnOrigin(t *testing.T) {
	idp := newMockIDP(t)
	srv, st := newOIDCServer(t, idp.server.Client())
	h := srv.Handler()
	if err := st.UpsertOIDCProvider(model.OIDCProvider{
		ID: "g", DisplayName: "Test", Issuer: idp.server.URL, ClientID: idp.clientID,
		ClientSecret: "s", AllowedDomains: []string{"example.com"}, Enabled: true,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?provider=g&redirect="+url.QueryEscape("/\t/evil.example/phish"), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: got %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	authURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	// A callback without the binding cookie fails as csrf and redirects to the
	// landing path the start stored.
	rec = oidcCallback(h, authURL.Query().Get("state"), "xyz", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "evil.example") || strings.ContainsAny(loc, "\t\r\n") {
		t.Fatalf("callback redirects to %q, which a browser resolves to another origin", loc)
	}
}
