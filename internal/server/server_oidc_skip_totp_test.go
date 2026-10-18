package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	oidctest "github.com/LatticeNet/lattice-server/internal/oidc"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The provider-trusted second factor (OIDCProvider.SkipLocalTOTP): a sign-in
// through a provider that carries it opens the console without the local
// authenticator code, but only through an identity link the account already
// confirmed with that code in its current security epoch. Everything that
// asks for a fresh second factor after sign-in keeps asking.

const (
	skipTOTPSecret   = "JBSWY3DPEHPK3PXP"
	skipTOTPUserID   = "u-2fa"
	skipTOTPEmail    = "twofa@example.com"
	skipTOTPSubject  = "sub-2fa"
	skipTOTPProvider = "g"
)

type skipTOTPFixture struct {
	idp *mockIDP
	srv *Server
	st  *store.Store
	h   http.Handler
}

// newSkipTOTPFixture is a server with one provider ("g", skip as given) and
// one account with local TOTP enabled whose username is the provider email.
func newSkipTOTPFixture(t *testing.T, skip bool, opts ...func(*Options)) *skipTOTPFixture {
	t.Helper()
	idp := newMockIDP(t)
	idp.sub = skipTOTPSubject
	idp.email = skipTOTPEmail
	idp.emailVerified = true
	st, err := store.OpenWithCipher("", nil)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Store: st, AdminPassword: testAdminPass, PublicURL: "https://lattice.test"}
	for _, f := range opts {
		f(&o)
	}
	srv, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	srv.oidc = oidctest.NewManagerWithClient(idp.server.Client())
	if err := st.UpsertOIDCProvider(model.OIDCProvider{
		ID: skipTOTPProvider, DisplayName: "Google", Issuer: idp.server.URL, ClientID: idp.clientID,
		AllowedDomains: []string{"example.com"}, Enabled: true, SkipLocalTOTP: skip, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUser(model.User{ID: skipTOTPUserID, Username: skipTOTPEmail, Scopes: []string{"node:read"}, TOTPEnabled: true, TOTPSecret: skipTOTPSecret}); err != nil {
		t.Fatal(err)
	}
	return &skipTOTPFixture{idp: idp, srv: srv, st: st, h: srv.Handler()}
}

// confirmLink stores the provider link as one the account confirmed with its
// local second factor in the given epoch.
func (f *skipTOTPFixture) confirmLink(t *testing.T, subject string, epoch uint64) {
	t.Helper()
	if err := f.st.PutOIDCIdentity(model.OIDCIdentity{
		ProviderID: skipTOTPProvider, Issuer: f.idp.server.URL, Subject: subject, UserID: skipTOTPUserID,
		Email: skipTOTPEmail, CreatedAt: time.Now().UTC(), SecondFactorAt: time.Now().UTC(), SecondFactorEpoch: epoch,
	}); err != nil {
		t.Fatal(err)
	}
}

// sso runs /start and /callback from one client address (state and any
// second-factor challenge are bound to it) and returns the callback response.
func (f *skipTOTPFixture) sso(t *testing.T, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?provider="+skipTOTPProvider, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: got %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	bind := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcBindingCookie {
			bind = c.Name + "=" + c.Value
		}
	}
	f.idp.nonce = u.Query().Get("nonce")
	cb := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state="+u.Query().Get("state")+"&code=xyz", nil)
	cb.RemoteAddr = remoteAddr
	cb.Header.Set("Cookie", bind)
	out := httptest.NewRecorder()
	f.h.ServeHTTP(out, cb)
	return out
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

// sessionFrom returns the session cookie the callback set and the CSRF token
// /api/me reports for it.
func (f *skipTOTPFixture) sessionFrom(t *testing.T, rec *httptest.ResponseRecorder) ([]*http.Cookie, string) {
	t.Helper()
	c := cookieNamed(rec, "lattice_session")
	if c == nil {
		t.Fatalf("no session cookie; Location=%s", rec.Header().Get("Location"))
	}
	cookies := []*http.Cookie{c}
	me := doJSON(t, f.h, http.MethodGet, "/api/me", "", cookies, "")
	defer me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("/api/me with the SSO session: %d", me.StatusCode)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(me.Body).Decode(&out); err != nil || out.CSRF == "" {
		t.Fatalf("/api/me csrf: %v %+v", err, out)
	}
	return cookies, out.CSRF
}

// assertSkipped checks the callback opened the console with no second-factor
// step: a session, a landing redirect without totp_challenge, no challenge
// cookie.
func assertSkipped(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "totp_challenge") || strings.Contains(loc, "sso_error") {
		t.Fatalf("callback should land without a challenge or error, got %s", loc)
	}
	if cookieNamed(rec, "lattice_session") == nil {
		t.Fatal("callback should start a session")
	}
	if cookieNamed(rec, totpChallengeCookie) != nil {
		t.Fatal("callback should not set a second-factor challenge cookie")
	}
}

// assertChallenged checks the callback asked for the local second factor and
// returns the challenge id and its browser-binding cookie.
func assertChallenged(t *testing.T, rec *httptest.ResponseRecorder) (string, *http.Cookie) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302", rec.Code)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || u.Query().Get("totp_challenge") == "" {
		t.Fatalf("expected a totp_challenge redirect, got %s", rec.Header().Get("Location"))
	}
	if cookieNamed(rec, "lattice_session") != nil {
		t.Fatal("a challenged callback must not start a session")
	}
	c := cookieNamed(rec, totpChallengeCookie)
	if c == nil {
		t.Fatal("a challenged callback must bind the challenge to the browser")
	}
	return u.Query().Get("totp_challenge"), c
}

func auditCount(st *store.Store, action string) int {
	n := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == action {
			n++
		}
	}
	return n
}

func TestOIDCSkipLocalTOTPOpensConfirmedLinkWithoutChallenge(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)

	rec := f.sso(t, "198.51.100.10:1000")
	assertSkipped(t, rec)
	f.sessionFrom(t, rec)

	var skipped *model.AuditEvent
	for _, ev := range f.st.AuditEvents() {
		if ev.Action == "login.oidc.totp_skipped" {
			ev := ev
			skipped = &ev
		}
	}
	if skipped == nil {
		t.Fatalf("missing login.oidc.totp_skipped audit: %+v", f.st.AuditEvents())
	}
	if skipped.Decision != "allow" || skipped.ActorID != skipTOTPUserID || skipped.Metadata["provider"] != skipTOTPProvider ||
		!strings.Contains(skipped.Reason, "provider policy") {
		t.Fatalf("skip audit does not say who, which provider and why: %+v", *skipped)
	}
	if n := auditCount(f.st, "login.oidc.totp_required"); n != 0 {
		t.Fatalf("a skipped sign-in must not also record a TOTP challenge, got %d", n)
	}
}

func TestOIDCSkipLocalTOTPOffKeepsChallenge(t *testing.T) {
	f := newSkipTOTPFixture(t, false)
	f.confirmLink(t, skipTOTPSubject, 0)

	assertChallenged(t, f.sso(t, "198.51.100.11:1000"))
	if auditCount(f.st, "login.oidc.totp_required") != 1 || auditCount(f.st, "login.oidc.totp_skipped") != 0 {
		t.Fatalf("flag off must challenge exactly as before: %+v", f.st.AuditEvents())
	}
}

func TestOIDCSkipLocalTOTPConfirmsFirstLinkWithTheLocalFactorOnce(t *testing.T) {
	f := newSkipTOTPFixture(t, true)

	// First sign-in through this subject: matched by email, never confirmed.
	addr := "198.51.100.12:1000"
	challengeID, challengeCookie := assertChallenged(t, f.sso(t, addr))
	if link, ok := f.st.OIDCIdentity(skipTOTPProvider, skipTOTPSubject); !ok || !link.SecondFactorAt.IsZero() {
		t.Fatalf("the first sign-in links the subject unconfirmed: %+v ok=%v", link, ok)
	}

	code, err := auth.TOTPCodeAt(skipTOTPSecret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login/totp", strings.NewReader(`{"challenge_id":"`+challengeID+`","code":"`+code+`"}`))
	req.RemoteAddr = addr
	req.AddCookie(challengeCookie)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || cookieNamed(rec, "lattice_session") == nil {
		t.Fatalf("second factor: %d %s", rec.Code, rec.Body.String())
	}
	link, ok := f.st.OIDCIdentity(skipTOTPProvider, skipTOTPSubject)
	if !ok || link.SecondFactorAt.IsZero() || link.SecondFactorEpoch != 0 {
		t.Fatalf("completing the SSO second factor must confirm the link: %+v ok=%v", link, ok)
	}

	// From now on the provider sign-in is the whole login.
	assertSkipped(t, f.sso(t, "198.51.100.13:1000"))
}

// answerChallenge posts a code (or, with recovery, a recovery code) for an
// SSO-issued challenge from addr, with the given cookie when not nil.
func (f *skipTOTPFixture) answerChallenge(t *testing.T, addr, challengeID, field, value string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/login/totp", strings.NewReader(`{"challenge_id":"`+challengeID+`","`+field+`":"`+value+`"}`))
	req.RemoteAddr = addr
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func TestOIDCSkipLocalTOTPConfirmationOnlyFromTheSSOBrowser(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	addr := "198.51.100.14:1000"
	challengeID, cookie := assertChallenged(t, f.sso(t, addr))
	code, _ := auth.TOTPCodeAt(skipTOTPSecret, time.Now().UTC())

	// The challenge id travels in the redirect URL. Neither leaving the cookie
	// out nor forging one from the id answers the challenge.
	if rec := f.answerChallenge(t, addr, challengeID, "code", code, nil); rec.Code != http.StatusUnauthorized || cookieNamed(rec, "lattice_session") != nil {
		t.Fatalf("an SSO challenge answered without its cookie: got %d, want 401 and no session", rec.Code)
	}
	forged := &http.Cookie{Name: totpChallengeCookie, Value: challengeID}
	if rec := f.answerChallenge(t, addr, challengeID, "code", code, forged); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an SSO challenge answered with a cookie forged from its id: got %d, want 401", rec.Code)
	}
	if link, _ := f.st.OIDCIdentity(skipTOTPProvider, skipTOTPSubject); !link.SecondFactorAt.IsZero() {
		t.Fatal("a refused answer confirmed the link")
	}
	// The real cookie still works, so the refusals above were for their stated reason.
	if rec := f.answerChallenge(t, addr, challengeID, "code", code, cookie); rec.Code != http.StatusOK {
		t.Fatalf("the SSO browser's answer: got %d, want 200", rec.Code)
	}
}

func TestOIDCSkipLocalTOTPRecoveryCodeDoesNotConfirm(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	user, _ := f.st.User(skipTOTPUserID)
	user.RecoveryCodeHashes = []string{auth.HashRecoveryCode("recovery-one")}
	if err := f.st.UpsertUser(user); err != nil {
		t.Fatal(err)
	}
	addr := "198.51.100.22:1000"
	challengeID, cookie := assertChallenged(t, f.sso(t, addr))
	if rec := f.answerChallenge(t, addr, challengeID, "recovery_code", "recovery-one", cookie); rec.Code != http.StatusOK || cookieNamed(rec, "lattice_session") == nil {
		t.Fatalf("a recovery code still finishes the sign-in: got %d", rec.Code)
	}
	if link, _ := f.st.OIDCIdentity(skipTOTPProvider, skipTOTPSubject); !link.SecondFactorAt.IsZero() {
		t.Fatal("a recovery code must not confirm the provider link")
	}
	assertChallenged(t, f.sso(t, "198.51.100.23:1000"))
}

func TestOIDCSkipLocalTOTPReadsThePolicyAfterTheExchange(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)
	// The operator turns the policy off while the callback is talking to the
	// provider.
	f.idp.onToken = func() {
		p, _ := f.st.OIDCProvider(skipTOTPProvider)
		p.SkipLocalTOTP = false
		if err := f.st.UpsertOIDCProvider(p); err != nil {
			t.Error(err)
		}
	}
	assertChallenged(t, f.sso(t, "198.51.100.24:1000"))
}

func TestSSOVouchesForSecondFactorNeedsEveryCondition(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)
	provider, _ := f.st.OIDCProvider(skipTOTPProvider)
	user, _ := f.st.User(skipTOTPUserID)
	if !f.srv.ssoVouchesForSecondFactor(provider, skipTOTPSubject, user) {
		t.Fatal("the fixture should vouch, or the cases below prove nothing")
	}
	disabled := provider
	disabled.Enabled = false
	flagOff := provider
	flagOff.SkipLocalTOTP = false
	repointed := provider
	repointed.Issuer = "https://idp.attacker.example"
	otherUser := user
	otherUser.ID = "u-other"
	laterEpoch := user
	laterEpoch.SecurityEpoch = 1
	cases := []struct {
		name     string
		provider model.OIDCProvider
		subject  string
		user     model.User
	}{
		{"disabled provider", disabled, skipTOTPSubject, user},
		{"policy off", flagOff, skipTOTPSubject, user},
		{"provider repointed at another issuer", repointed, skipTOTPSubject, user},
		{"unknown subject", provider, "sub-unknown", user},
		{"link names another user", provider, skipTOTPSubject, otherUser},
		{"security epoch moved on", provider, skipTOTPSubject, laterEpoch},
	}
	for _, tc := range cases {
		if f.srv.ssoVouchesForSecondFactor(tc.provider, tc.subject, tc.user) {
			t.Errorf("%s: must not vouch", tc.name)
		}
	}
	if err := f.st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: skipTOTPProvider, Issuer: f.idp.server.URL, Subject: skipTOTPSubject, UserID: skipTOTPUserID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if f.srv.ssoVouchesForSecondFactor(provider, skipTOTPSubject, user) {
		t.Error("an unconfirmed link must not vouch")
	}
}

func TestOIDCSkipLocalTOTPNotifiesWhenAnAccountBecomesTrusted(t *testing.T) {
	for _, skip := range []bool{true, false} {
		f := newSkipTOTPFixture(t, skip)
		var sent []string
		f.srv.emitNotify = func(title, body string) { sent = append(sent, title+": "+body) }
		addr := "198.51.100.25:1000"
		challengeID, cookie := assertChallenged(t, f.sso(t, addr))
		code, _ := auth.TOTPCodeAt(skipTOTPSecret, time.Now().UTC())
		if rec := f.answerChallenge(t, addr, challengeID, "code", code, cookie); rec.Code != http.StatusOK {
			t.Fatalf("skip=%v: second factor: %d", skip, rec.Code)
		}
		want := 0
		if skip {
			want = 1
		}
		if len(sent) != want {
			t.Fatalf("skip=%v: notifications = %q, want %d", skip, sent, want)
		}
		if skip && (!strings.Contains(sent[0], skipTOTPEmail) || strings.Contains(sent[0], skipTOTPSubject)) {
			t.Fatalf("the notification names the account and masks the subject: %q", sent[0])
		}
		var confirmed *model.AuditEvent
		for _, ev := range f.st.AuditEvents() {
			if ev.Action == "login.oidc.second_factor_confirmed" {
				ev := ev
				confirmed = &ev
			}
		}
		if confirmed == nil || confirmed.Metadata["newly_trusted"] != strconv.FormatBool(skip) || confirmed.Metadata["subject"] != maskSSOSubject(skipTOTPSubject) {
			t.Fatalf("skip=%v: confirmation audit: %+v", skip, confirmed)
		}
	}
}

func TestPasswordTOTPIgnoresAStaleSSOChallengeCookie(t *testing.T) {
	f := newSkipTOTPFixture(t, false)
	addr := "198.51.100.26:1000"
	_, ssoCookie := assertChallenged(t, f.sso(t, addr))

	// The operator abandons the SSO step and signs in with the password.
	admin, _ := f.st.UserByUsername("admin")
	admin.TOTPEnabled, admin.TOTPSecret = true, skipTOTPSecret
	if err := f.st.UpsertUser(admin); err != nil {
		t.Fatal(err)
	}
	required, challengeID, _ := passwordLogin(t, f.h, addr)
	if !required {
		t.Fatal("password login must ask for TOTP")
	}
	code, _ := auth.TOTPCodeAt(skipTOTPSecret, time.Now().UTC())
	rec := f.answerChallenge(t, addr, challengeID, "code", code, ssoCookie)
	if rec.Code != http.StatusOK || cookieNamed(rec, "lattice_session") == nil {
		t.Fatalf("a leftover SSO cookie must not block the password path's second factor: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOIDCSkipLocalTOTPUnconfirmedSecondSubjectStillChallenged(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)

	// Another provider account asserting the same verified email binds by
	// email match; the account never confirmed it, so the code is asked.
	f.idp.sub = "sub-someone-else"
	assertChallenged(t, f.sso(t, "198.51.100.15:1000"))
}

func TestOIDCSkipLocalTOTPEpochBumpWithdrawsTrust(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)
	user, _ := f.st.User(skipTOTPUserID)
	user.SecurityEpoch++ // a password change, 2FA disable or admin revoke
	if err := f.st.UpsertUser(user); err != nil {
		t.Fatal(err)
	}
	assertChallenged(t, f.sso(t, "198.51.100.16:1000"))
}

func TestOIDCSkipLocalTOTPDisabledProviderStillRefused(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)

	// The provider is disabled after the sign-in started.
	addr := "198.51.100.17:1000"
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?provider="+skipTOTPProvider, nil)
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	u, _ := url.Parse(rec.Header().Get("Location"))
	bind := cookieNamed(rec, oidcBindingCookie)
	f.idp.nonce = u.Query().Get("nonce")
	p, _ := f.st.OIDCProvider(skipTOTPProvider)
	p.Enabled = false
	if err := f.st.UpsertOIDCProvider(p); err != nil {
		t.Fatal(err)
	}
	cb := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state="+u.Query().Get("state")+"&code=xyz", nil)
	cb.RemoteAddr = addr
	cb.AddCookie(bind)
	out := httptest.NewRecorder()
	f.h.ServeHTTP(out, cb)
	if cookieNamed(out, "lattice_session") != nil || !strings.Contains(out.Header().Get("Location"), "sso_error=unavailable") {
		t.Fatalf("a disabled provider must refuse the callback: %d %s", out.Code, out.Header().Get("Location"))
	}
	if auditCount(f.st, "login.oidc.totp_skipped") != 0 {
		t.Fatal("a refused callback must not record a skip")
	}

	// And a new sign-in cannot even start.
	start := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/start?provider="+skipTOTPProvider, nil)
	start.RemoteAddr = "198.51.100.18:1000"
	srec := httptest.NewRecorder()
	f.h.ServeHTTP(srec, start)
	if srec.Code != http.StatusNotFound {
		t.Fatalf("start against a disabled provider: got %d, want 404", srec.Code)
	}
}

func TestPasswordLoginStillRequiresTOTPWithSkipProvider(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	admin, ok := f.st.UserByUsername("admin")
	if !ok {
		t.Fatal("admin missing")
	}
	admin.TOTPEnabled, admin.TOTPSecret = true, skipTOTPSecret
	if err := f.st.UpsertUser(admin); err != nil {
		t.Fatal(err)
	}
	// Even an account whose provider link is confirmed keeps the code on the
	// password path.
	if err := f.st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: skipTOTPProvider, Subject: "sub-admin", UserID: admin.ID,
		CreatedAt: time.Now().UTC(), SecondFactorAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	totpRequired, challengeID, cookies := passwordLogin(t, f.h, "198.51.100.19:1000")
	if !totpRequired || challengeID == "" || hasSessionCookie(cookies) {
		t.Fatalf("password login must still ask for TOTP: required=%v challenge=%q session=%v", totpRequired, challengeID, hasSessionCookie(cookies))
	}
}

func TestSkippedTOTPSessionStillNeedsStepUp(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)
	rec := f.sso(t, "198.51.100.20:1000")
	assertSkipped(t, rec)
	cookies, csrf := f.sessionFrom(t, rec)

	// Registering a passkey asks a TOTP account for a fresh step-up.
	denied := doJSON(t, f.h, http.MethodPost, "/api/security/webauthn/register/begin", `{}`, cookies, csrf)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("passkey registration without step-up: got %d, want 403", denied.StatusCode)
	}
	// Turning TOTP off still needs a current code.
	off := doJSON(t, f.h, http.MethodPost, "/api/2fa/totp/disable", `{"code":""}`, cookies, csrf)
	off.Body.Close()
	if off.StatusCode != http.StatusUnauthorized {
		t.Fatalf("2fa disable without a code: got %d, want 401", off.StatusCode)
	}
	if u, _ := f.st.User(skipTOTPUserID); !u.TOTPEnabled {
		t.Fatal("2fa was turned off without a code")
	}
	// The secret-reveal gate refuses a session without a grant.
	sessionID := cookies[0].Value
	if d := f.srv.decideSecretReveal(principal{Principal: rbac.Principal{ActorID: skipTOTPUserID}, sessionID: sessionID}, ""); d.Allowed || d.Code != apiErrorStepUpRequired {
		t.Fatalf("secret reveal without step-up: %+v", d)
	}
	// A wrong code earns no grant; the right one does, and then the action passes.
	wrong := doJSON(t, f.h, http.MethodPost, "/api/security/step-up", `{"code":"000000"}`, cookies, csrf)
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("step-up with a wrong code: got %d, want 401", wrong.StatusCode)
	}
	code, _ := auth.TOTPCodeAt(skipTOTPSecret, time.Now().UTC())
	ok := doJSON(t, f.h, http.MethodPost, "/api/security/step-up", `{"code":"`+code+`"}`, cookies, csrf)
	defer ok.Body.Close()
	var grant struct {
		Grant string `json:"grant"`
	}
	if ok.StatusCode != http.StatusOK || json.NewDecoder(ok.Body).Decode(&grant) != nil || grant.Grant == "" {
		t.Fatalf("step-up with the right code: %d", ok.StatusCode)
	}
	allowed := doJSON(t, f.h, http.MethodPost, "/api/security/webauthn/register/begin", `{"step_up_grant":"`+grant.Grant+`"}`, cookies, csrf)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("passkey registration with a fresh grant: got %d, want 200", allowed.StatusCode)
	}
	if d := f.srv.decideSecretReveal(principal{Principal: rbac.Principal{ActorID: skipTOTPUserID}, sessionID: sessionID}, grant.Grant); !d.Allowed {
		t.Fatalf("secret reveal with a fresh grant: %+v", d)
	}
}

func TestRequireTOTPPolicyStillForcesEnrollmentAfterSkipProvider(t *testing.T) {
	f := newSkipTOTPFixture(t, true, func(o *Options) { o.RequireTOTP = true })
	// An account without TOTP: there is nothing for the provider to stand in
	// for, and the server policy still forces enrollment.
	user, _ := f.st.User(skipTOTPUserID)
	user.TOTPEnabled, user.TOTPSecret = false, ""
	if err := f.st.UpsertUser(user); err != nil {
		t.Fatal(err)
	}
	f.confirmLink(t, skipTOTPSubject, 0)
	rec := f.sso(t, "198.51.100.21:1000")
	cookies, csrf := f.sessionFrom(t, rec)
	if auditCount(f.st, "login.oidc.totp_skipped") != 0 {
		t.Fatal("an account without TOTP has no second factor to skip")
	}
	nodes := doJSON(t, f.h, http.MethodGet, "/api/nodes", "", cookies, csrf)
	defer nodes.Body.Close()
	var body model.APIErrorResponse
	if nodes.StatusCode != http.StatusForbidden || json.NewDecoder(nodes.Body).Decode(&body) != nil || body.Error.Code != model.APIErrorMFARequired {
		t.Fatalf("enrollment gate after SSO: %d %+v", nodes.StatusCode, body)
	}
}

// adminStepUp mints a step-up grant for the admin session in cookie, as the
// TOTP or passkey step-up endpoint would after a fresh second factor.
func adminStepUp(t *testing.T, srv *Server, st *store.Store, cookie string) string {
	t.Helper()
	admin, ok := st.UserByUsername("admin")
	if !ok {
		t.Fatal("admin missing")
	}
	sessionID := strings.TrimPrefix(cookie, "lattice_session=")
	grant, _, err := srv.issueStepUpGrant(principal{Principal: rbac.Principal{ActorID: admin.ID}, sessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestOIDCAdminProviderSkipLocalTOTPRoundTripAndAudit(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	cookie, csrf := adminLogin(t, h)

	const create = `{"display_name":"G","issuer":"https://accounts.google.com","client_id":"cid","enabled":true,"skip_local_totp":true`
	// Turning it on asks for a fresh step-up.
	rec := adminPOST(t, h, "/api/auth/oidc/providers", create+`}`, cookie, csrf)
	var refused model.APIErrorResponse
	if rec.Code != http.StatusForbidden || json.Unmarshal(rec.Body.Bytes(), &refused) != nil || refused.Error.Code != apiErrorStepUpRequired {
		t.Fatalf("turning skip_local_totp on without step-up: %d %s", rec.Code, rec.Body.String())
	}
	if len(st.OIDCProviders()) != 0 {
		t.Fatal("a refused create must store nothing")
	}
	rec = adminPOST(t, h, "/api/auth/oidc/providers", create+`,"step_up_grant":"`+adminStepUp(t, srv, st, cookie)+`"}`, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID            string `json:"id"`
		SkipLocalTOTP *bool  `json:"skip_local_totp"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.SkipLocalTOTP == nil || !*created.SkipLocalTOTP {
		t.Fatalf("create response must return skip_local_totp=true: %s", rec.Body.String())
	}
	if p, _ := st.OIDCProvider(created.ID); !p.SkipLocalTOTP {
		t.Fatal("skip_local_totp was not stored")
	}

	// An update that leaves the field out turns it off, the safe value, and
	// needs no step-up.
	rec = adminPOST(t, h, "/api/auth/oidc/providers",
		`{"id":"`+created.ID+`","issuer":"https://accounts.google.com","client_id":"cid","enabled":true}`, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if p, _ := st.OIDCProvider(created.ID); p.SkipLocalTOTP {
		t.Fatal("an update without skip_local_totp must store false")
	}

	get := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/providers", nil)
	get.Header.Set("Cookie", cookie)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, get)
	if !strings.Contains(getRec.Body.String(), `"skip_local_totp":false`) {
		t.Fatalf("the admin list must state skip_local_totp explicitly: %s", getRec.Body.String())
	}

	// AuditEvents lists newest first; compare as a set of (old, new) pairs.
	changes := map[[2]string]int{}
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" && ev.Metadata["provider"] == created.ID {
			changes[[2]string{ev.Metadata["old_skip_local_totp"], ev.Metadata["new_skip_local_totp"]}]++
		}
	}
	want := map[[2]string]int{{"false", "true"}: 1, {"true", "false"}: 1}
	if len(changes) != len(want) || changes[[2]string{"false", "true"}] != 1 || changes[[2]string{"true", "false"}] != 1 {
		t.Fatalf("upsert audits must carry old and new skip_local_totp, got %v want %v", changes, want)
	}
}

func TestOIDCSkipLocalTOTPTurningOnClearsEarlierConfirmations(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	const issuer = "https://accounts.google.com"
	if err := st.UpsertOIDCProvider(model.OIDCProvider{ID: skipTOTPProvider, Issuer: issuer, ClientID: "cid", Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	// Confirmed while the policy was off, for example months before.
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: skipTOTPProvider, Issuer: issuer, Subject: skipTOTPSubject, UserID: skipTOTPUserID,
		CreatedAt: time.Now().UTC(), SecondFactorAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := adminLogin(t, h)
	body := `{"id":"` + skipTOTPProvider + `","issuer":"` + issuer + `","client_id":"cid","enabled":true,"skip_local_totp":true,"step_up_grant":"` +
		adminStepUp(t, srv, st, cookie) + `"}`
	if rec := adminPOST(t, h, "/api/auth/oidc/providers", body, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("turn on: %d %s", rec.Code, rec.Body.String())
	}
	if link, ok := st.OIDCIdentity(skipTOTPProvider, skipTOTPSubject); !ok || !link.SecondFactorAt.IsZero() {
		t.Fatalf("turning the policy on must clear confirmations made before it and keep the link: %+v ok=%v", link, ok)
	}
	cleared := ""
	for _, ev := range st.AuditEvents() {
		if ev.Action == "oidc.provider.upsert" && ev.Decision == "allow" {
			cleared = ev.Metadata["confirmations_cleared"]
		}
	}
	if cleared != "1" {
		t.Fatalf("the upsert audit must say how many confirmations it cleared, got %q", cleared)
	}
}

func TestOIDCSkipLocalTOTPBearerTokenCannotTurnItOn(t *testing.T) {
	srv, st := newOIDCServer(t)
	h := srv.Handler()
	cookies, csrf := loginSession(t, h)
	token := createPAT(t, h, cookies, csrf, []string{"oidc:admin"}, nil)
	res := doBearerJSON(t, h, http.MethodPost, "/api/auth/oidc/providers",
		`{"issuer":"https://accounts.google.com","client_id":"cid","enabled":true,"skip_local_totp":true,"step_up_grant":"anything"}`, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden || len(st.OIDCProviders()) != 0 {
		t.Fatalf("a token turning skip_local_totp on: got %d, providers=%d", res.StatusCode, len(st.OIDCProviders()))
	}
}

func TestOIDCDeleteProviderClearsConfirmations(t *testing.T) {
	f := newSkipTOTPFixture(t, true)
	f.confirmLink(t, skipTOTPSubject, 0)
	cookie, csrf := adminLogin(t, f.h)
	if rec := adminPOST(t, f.h, "/api/auth/oidc/providers/delete", `{"id":"`+skipTOTPProvider+`"}`, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if link, ok := f.st.OIDCIdentity(skipTOTPProvider, skipTOTPSubject); !ok || !link.SecondFactorAt.IsZero() {
		t.Fatalf("a deleted provider's links keep no confirmation: %+v ok=%v", link, ok)
	}
}
