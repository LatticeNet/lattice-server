package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	oidctest "github.com/LatticeNet/lattice-server/internal/oidc"
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
	idp.server = newLocalOIDCTestServer(t, mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func newLocalOIDCTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable in this environment: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	return srv
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

func newOIDCServer(t *testing.T, clients ...*http.Client) (*Server, *store.Store) {
	t.Helper()
	st, err := store.OpenWithCipher("", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: "correct horse battery staple", PublicURL: "https://lattice.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) > 0 {
		srv.oidc = oidctest.NewManagerWithClient(clients[0])
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

	srv, st := newOIDCServer(t, idp.server.Client())
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

	srv, st := newOIDCServer(t, idp.server.Client())
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

	srv, st := newOIDCServer(t, idp.server.Client())
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

// ssoToSecondFactor runs an SSO login for a 2FA user up to the second-factor
// step and returns the challenge id from the redirect and the browser-binding
// cookie ("name=value") the callback set.
func ssoToSecondFactor(t *testing.T, h http.Handler, idp *mockIDP, providerID string) (challengeID, challengeCookie string) {
	t.Helper()
	state, nonce, bind := startAndParse(t, h, providerID)
	idp.nonce = nonce
	rec := oidcCallback(h, state, "xyz", bind)
	u, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || u.Query().Get("totp_challenge") == "" {
		t.Fatalf("expected a totp_challenge redirect, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == totpChallengeCookie && c.Value != "" {
			return u.Query().Get("totp_challenge"), c.Name + "=" + c.Value
		}
	}
	t.Fatal("callback did not set the second-factor challenge cookie")
	return "", ""
}

// getPendingSecondFactor reads GET /api/login/totp with an optional cookie
// header and client address (httptest's default address when empty).
func getPendingSecondFactor(h http.Handler, cookie, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/login/totp", nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodePendingSecondFactor(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("pending second factor: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("pending second factor must not be cached; Cache-Control=%q", got)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	return out
}

func TestOIDCPendingSecondFactorNamesProviderAndEmail(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-2fa"
	idp.email = "twofa@example.com"
	idp.emailVerified = true

	srv, st := newOIDCServer(t, idp.server.Client())
	h := srv.Handler()
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "g", DisplayName: "Google", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, AllowedDomains: []string{"example.com"}, CreatedAt: time.Now().UTC()})
	st.UpsertUser(model.User{ID: "u-2fa", Username: "twofa@example.com", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"})

	challengeID, cookie := ssoToSecondFactor(t, h, idp, "g")

	got := decodePendingSecondFactor(t, getPendingSecondFactor(h, cookie, ""))
	want := map[string]any{"provider": "Google", "email": "twofa@example.com"}
	if len(got) != len(want) || got["provider"] != want["provider"] || got["email"] != want["email"] {
		t.Fatalf("pending second factor = %v, want exactly %v", got, want)
	}

	// The read is not a way around the second factor and does not spend the
	// challenge: no session cookie, and the code still completes the login.
	if rec := getPendingSecondFactor(h, cookie, ""); hasSessionCookie(rec.Result().Cookies()) {
		t.Fatal("reading the pending second factor must not set a session")
	}
	code, err := auth.TOTPCodeAt("JBSWY3DPEHPK3PXP", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login/totp", strings.NewReader(`{"challenge_id":"`+challengeID+`","code":"`+code+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !hasSessionCookie(rec.Result().Cookies()) {
		t.Fatalf("second factor after the read: got %d; body=%s", rec.Code, rec.Body.String())
	}

	// Once the sign-in completes the challenge is spent and names nobody.
	if rec := getPendingSecondFactor(h, cookie, ""); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "twofa@") {
		t.Fatalf("completed sign-in: got %d %s, want 404 naming nobody", rec.Code, rec.Body.String())
	}
}

func TestOIDCPendingSecondFactorFallsBackToSubject(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-unverified"
	idp.email = "unverified@example.com"
	idp.emailVerified = false // an unverified email is not shown as verified

	srv, st := newOIDCServer(t, idp.server.Client())
	h := srv.Handler()
	// No display name: the provider id stands in for it.
	st.UpsertOIDCProvider(model.OIDCProvider{ID: "corp", Issuer: idp.server.URL, ClientID: idp.clientID, Enabled: true, CreatedAt: time.Now().UTC()})
	st.UpsertUser(model.User{ID: "u-sub", Username: "operator", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"})
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "corp", Issuer: idp.server.URL, Subject: "sub-unverified", UserID: "u-sub", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	_, cookie := ssoToSecondFactor(t, h, idp, "corp")

	got := decodePendingSecondFactor(t, getPendingSecondFactor(h, cookie, ""))
	if len(got) != 2 || got["provider"] != "corp" || got["subject"] != "sub-unverified" {
		t.Fatalf("pending second factor = %v, want exactly provider=corp subject=sub-unverified", got)
	}
}

func TestPendingSecondFactorNamesNobodyWithoutAValidSSOChallenge(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	st.UpsertUser(model.User{ID: "u-2fa", Username: "twofa@example.com", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"})
	st.UpsertUser(model.User{ID: "u-plain", Username: "plain@example.com"})
	ip := srv.clientIP(httptest.NewRequest(http.MethodGet, "/", nil))

	put := func(userID string, ttl time.Duration, sso bool) string {
		t.Helper()
		c, err := auth.NewTOTPChallenge(userID, ip, ttl)
		if err != nil {
			t.Fatal(err)
		}
		if sso {
			c.SSOProviderID, c.SSOEmail, c.SSOSubject = "g", "twofa@example.com", "sub-2fa"
		}
		if err := st.PutTOTPChallenge(c); err != nil {
			t.Fatal(err)
		}
		return totpChallengeCookie + "=" + c.ID
	}
	valid := put("u-2fa", 5*time.Minute, true)
	passwordPath := put("u-2fa", 5*time.Minute, false)
	without2FA := put("u-plain", 5*time.Minute, true)
	// Last, because every put sweeps the challenges that are no longer active.
	expired := put("u-2fa", -time.Minute, true)

	cases := []struct {
		name, cookie, remoteAddr string
	}{
		{"no cookie", "", ""},
		{"unknown challenge", totpChallengeCookie + "=" + strings.Repeat("a", 43), ""},
		{"expired challenge", expired, ""},
		{"password-path challenge", passwordPath, ""},
		{"user without 2fa", without2FA, ""},
		{"another network", valid, "203.0.113.9:4000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := getPendingSecondFactor(h, tc.cookie, tc.remoteAddr)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("got %d, want 404; body=%s", rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); strings.Contains(body, "twofa@") || strings.Contains(body, "sub-2fa") {
				t.Fatalf("a refused read must name nobody; body=%s", body)
			}
		})
	}

	// The same valid challenge from its own network does answer, so the cases
	// above fail for their stated reason and not for a broken fixture.
	if got := decodePendingSecondFactor(t, getPendingSecondFactor(h, valid, "")); got["email"] != "twofa@example.com" {
		t.Fatalf("valid challenge = %v", got)
	}
}

func TestOIDCCallbackRejectsNonceMismatch(t *testing.T) {
	idp := newMockIDP(t)
	idp.sub = "sub-x"
	idp.email = "x@example.com"
	idp.emailVerified = true

	srv, st := newOIDCServer(t, idp.server.Client())
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

	srv, st := newOIDCServer(t, idp.server.Client())
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

func TestOIDCDefaultClientBlocksInternalIssuer(t *testing.T) {
	srv, _ := newOIDCServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := srv.oidc.Probe(ctx, "https://127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("default OIDC client must block internal issuers, got %v", err)
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
