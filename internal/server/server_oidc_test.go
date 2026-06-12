package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// --- mock OpenID Provider -------------------------------------------------

type mockIDP struct {
	server        *httptest.Server
	key           *rsa.PrivateKey
	kid           string
	mu            sync.Mutex
	sub           string
	email         string
	emailVerified bool
	nonce         string // set by the test after /start
	clientID      string
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &mockIDP{key: key, kid: "test-key-1", clientID: "client-abc"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := idp.server.URL
		writeJSONRaw(w, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/auth",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := idp.key.PublicKey
		writeJSONRaw(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": idp.kid, "use": "sig", "alg": "RS256",
			"n": b64url(pub.N.Bytes()),
			"e": b64url(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		now := time.Now().Unix()
		claims := map[string]any{
			"iss":            idp.server.URL,
			"aud":            idp.clientID,
			"sub":            idp.sub,
			"email":          idp.email,
			"email_verified": idp.emailVerified,
			"nonce":          idp.nonce,
			"iat":            now,
			"exp":            now + 3600,
		}
		writeJSONRaw(w, map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idp.signJWT(claims),
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (m *mockIDP) signJWT(claims map[string]any) string {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": m.kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64url(hb) + "." + b64url(cb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, sum[:])
	return signingInput + "." + b64url(sig)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSONRaw(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- helpers --------------------------------------------------------------

func newOIDCServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.OpenWithCipher("", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: "correct horse battery staple", PublicURL: "https://lattice.test"})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

// startAndParse performs /start and returns the state+nonce from the redirect
// plus the browser-binding cookie ("name=value") the callback must echo back.
func startAndParse(t *testing.T, h http.Handler, providerID string) (state, nonce, bindCookie string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?provider="+providerID, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: got %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "lattice_oidc_bind" {
			bindCookie = c.Name + "=" + c.Value
		}
	}
	if bindCookie == "" {
		t.Fatal("start did not set the browser-binding cookie")
	}
	return u.Query().Get("state"), u.Query().Get("nonce"), bindCookie
}

// oidcCallback issues a callback request carrying the binding cookie.
func oidcCallback(h http.Handler, state, code, bindCookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state="+state+"&code="+code, nil)
	if bindCookie != "" {
		req.Header.Set("Cookie", bindCookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- tests ----------------------------------------------------------------

func TestOIDCEndToEndLogin(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-alice"
	idp.email = "alice@example.com"
	idp.emailVerified = true

	srv, st := newOIDCServer(t)
	h := srv.Handler()

	if err := st.UpsertOIDCProvider(model.OIDCProvider{
		ID: "g", DisplayName: "Test", Issuer: idp.server.URL, ClientID: idp.clientID,
		ClientSecret: "s", AllowedDomains: []string{"example.com"}, Enabled: true,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	// Pre-provision the local user (username == email). No auto-provision.
	if err := st.UpsertUser(model.User{ID: "u-alice", Username: "alice@example.com", Scopes: []string{"node:read"}}); err != nil {
		t.Fatal(err)
	}

	state, nonce, bind := startAndParse(t, h, "g")
	if state == "" || nonce == "" {
		t.Fatal("state and nonce must be in the redirect")
	}
	idp.nonce = nonce

	rec := oidcCallback(h, state, "xyz", bind)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if !hasSessionCookie(rec.Result().Cookies()) {
		t.Fatal("expected a session cookie to be set on successful SSO login")
	}

	// The link must now exist, keyed on the provider record and bound to the user.
	link, ok := st.OIDCIdentity("g", "sub-alice")
	if !ok || link.UserID != "u-alice" {
		t.Fatalf("identity link not created: %+v ok=%v", link, ok)
	}

	// Second login uses the existing link (email may change, but the domain
	// policy is still satisfied).
	idp.email = "alice-renamed@example.com"
	state2, nonce2, bind2 := startAndParse(t, h, "g")
	idp.nonce = nonce2
	rec2 := oidcCallback(h, state2, "xyz", bind2)
	if rec2.Code != http.StatusFound || !hasSessionCookie(rec2.Result().Cookies()) {
		t.Fatalf("second login via existing link failed: %d", rec2.Code)
	}
}

func TestOIDCCallbackRequiresBindingCookie(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-csrf"
	idp.email = "csrf@example.com"
	idp.emailVerified = true

	srv, st := newOIDCServer(t)
	h := srv.Handler()
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, AllowedDomains: []string{"example.com"}, CreatedAt: time.Now().UTC()})
	st.UpsertUser(model.User{ID: "u-csrf", Username: "csrf@example.com"})

	state, nonce, _ := startAndParse(t, h, "g")
	idp.nonce = nonce
	// Callback WITHOUT the browser-binding cookie must be rejected (login-CSRF).
	rec := oidcCallback(h, state, "xyz", "")
	if hasSessionCookie(rec.Result().Cookies()) {
		t.Fatal("callback without the binding cookie must not produce a session")
	}
	if !strings.Contains(rec.Header().Get("Location"), "sso_error=csrf") {
		t.Fatalf("expected sso_error=csrf, got %s", rec.Header().Get("Location"))
	}

	// A forged/mismatched binding cookie is likewise rejected.
	state2, nonce2, _ := startAndParse(t, h, "g")
	idp.nonce = nonce2
	rec2 := oidcCallback(h, state2, "xyz", "lattice_oidc_bind=forged-value")
	if hasSessionCookie(rec2.Result().Cookies()) || !strings.Contains(rec2.Header().Get("Location"), "sso_error=csrf") {
		t.Fatalf("forged binding cookie must be rejected as csrf; got %d %s", rec2.Code, rec2.Header().Get("Location"))
	}
}

func TestOIDCHonorsLocalTOTP(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-2fa"
	idp.email = "twofa@example.com"
	idp.emailVerified = true

	srv, st := newOIDCServer(t)
	h := srv.Handler()
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, AllowedDomains: []string{"example.com"}, CreatedAt: time.Now().UTC()})
	// A user with local 2FA enabled.
	st.UpsertUser(model.User{ID: "u-2fa", Username: "twofa@example.com", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"})

	state, nonce, bind := startAndParse(t, h, "g")
	idp.nonce = nonce
	rec := oidcCallback(h, state, "xyz", bind)
	if rec.Code != http.StatusFound {
		t.Fatalf("want redirect, got %d", rec.Code)
	}
	if hasSessionCookie(rec.Result().Cookies()) {
		t.Fatal("2FA user must NOT get a session straight from SSO; the second factor is still required")
	}
	if !strings.Contains(rec.Header().Get("Location"), "totp_challenge=") {
		t.Fatalf("expected a totp_challenge redirect, got %s", rec.Header().Get("Location"))
	}
}

func TestOIDCCallbackRejectsNonceMismatch(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-x"
	idp.email = "x@example.com"
	idp.emailVerified = true

	srv, st := newOIDCServer(t)
	h := srv.Handler()
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, AllowedDomains: []string{"example.com"}, CreatedAt: time.Now().UTC()})
	st.UpsertUser(model.User{ID: "ux", Username: "x@example.com"})

	state, _, bind := startAndParse(t, h, "g")
	idp.nonce = "attacker-controlled-different-nonce" // != the real nonce

	rec := oidcCallback(h, state, "xyz", bind)
	if rec.Code != http.StatusFound {
		t.Fatalf("want redirect, got %d", rec.Code)
	}
	if hasSessionCookie(rec.Result().Cookies()) {
		t.Fatal("nonce mismatch must not produce a session")
	}
	if !strings.Contains(rec.Header().Get("Location"), "sso_error=verify_failed") {
		t.Fatalf("expected verify_failed, got %s", rec.Header().Get("Location"))
	}
}

func TestOIDCCallbackDeniesUnprovisionedUser(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-ghost"
	idp.email = "ghost@example.com"
	idp.emailVerified = true

	srv, st := newOIDCServer(t)
	h := srv.Handler()
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, AllowedDomains: []string{"example.com"}, CreatedAt: time.Now().UTC()})
	// No local user for ghost@example.com.

	state, nonce, bind := startAndParse(t, h, "g")
	idp.nonce = nonce
	rec := oidcCallback(h, state, "xyz", bind)
	if hasSessionCookie(rec.Result().Cookies()) {
		t.Fatal("unprovisioned user must be denied (no auto-provision)")
	}
	if !strings.Contains(rec.Header().Get("Location"), "sso_error=denied") {
		t.Fatalf("expected denied, got %s", rec.Header().Get("Location"))
	}
}

func TestOIDCCallbackUnknownStateExpired(t *testing.T) {
	srv, _ := newOIDCServer(t)
	h := srv.Handler()
	rec := oidcCallback(h, "nope", "xyz", "")
	if hasSessionCookie(rec.Result().Cookies()) || !strings.Contains(rec.Header().Get("Location"), "sso_error=expired") {
		t.Fatalf("unknown state should redirect expired; got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOIDCStartUnknownProvider(t *testing.T) {
	srv, _ := newOIDCServer(t)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?provider=nope", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown provider, got %d", rec.Code)
	}
}

func TestOIDCListExposesNoSecrets(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "on", DisplayName: "On", Issuer: "https://i", ClientID: "c", ClientSecret: "topsecret", Enabled: true, CreatedAt: time.Now().UTC()})
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "off", DisplayName: "Off", Issuer: "https://i2", ClientID: "c", Enabled: false, CreatedAt: time.Now().UTC()})

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "topsecret") {
		t.Fatal("public list leaked a client secret")
	}
	if !strings.Contains(body, `"On"`) || strings.Contains(body, `"Off"`) {
		t.Fatalf("list should include enabled only: %s", body)
	}
}

func TestOIDCAdminProviderSecretWriteOnly(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	cookie, csrf := adminLogin(t, h)

	// Create with a secret.
	body := `{"display_name":"G","issuer":"https://accounts.google.com","client_id":"cid","client_secret":"mysecret","enabled":true}`
	rec := adminPOST(t, h, "/api/auth/oidc/providers", body, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "mysecret") {
		t.Fatal("create response leaked the secret")
	}
	var created struct {
		ID        string `json:"id"`
		HasSecret bool   `json:"has_secret"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if !created.HasSecret || created.ID == "" {
		t.Fatalf("expected has_secret + id: %+v", created)
	}

	// Update other fields with empty secret → stored secret preserved.
	upd := `{"id":"` + created.ID + `","issuer":"https://accounts.google.com","client_id":"cid2","client_secret":"","enabled":true}`
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", upd, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := st.OIDCProvider(created.ID)
	if got.ClientSecret != "mysecret" {
		t.Fatalf("empty-secret update should preserve stored secret, got %q", got.ClientSecret)
	}
	if got.ClientID != "cid2" {
		t.Fatalf("client_id should have updated, got %q", got.ClientID)
	}

	// GET list never includes the secret.
	get := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/providers", nil)
	get.Header.Set("Cookie", cookie)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", getRec.Code, getRec.Body.String())
	}
	if strings.Contains(getRec.Body.String(), "mysecret") {
		t.Fatal("admin list leaked the secret")
	}
}

// --- small auth helpers reused by admin tests -----------------------------

// adminLogin logs in as the bootstrap admin and returns the session Cookie
// header value and the CSRF token.
func adminLogin(t *testing.T, h http.Handler) (cookie, csrf string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin login failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "lattice_session" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" || resp.CSRF == "" {
		t.Fatal("admin login did not yield a session cookie + csrf")
	}
	return cookie, resp.CSRF
}

func adminPOST(t *testing.T, h http.Handler, path, body, cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("X-Lattice-CSRF", csrf)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
