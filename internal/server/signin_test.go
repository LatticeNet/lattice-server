package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

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
