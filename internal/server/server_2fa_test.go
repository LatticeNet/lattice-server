package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// doLoginFrom issues a login-family request from a specific client IP so each
// login pair stays under the per-IP login burst and matches the challenge's
// IP binding.
func doLoginFrom(t *testing.T, handler http.Handler, path, body, remoteAddr string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func passwordLogin(t *testing.T, handler http.Handler, remoteAddr string) (totpRequired bool, challengeID string, cookies []*http.Cookie) {
	t.Helper()
	res := doLoginFrom(t, handler, "/api/login", `{"username":"admin","password":"`+testAdminPass+`"}`, remoteAddr)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("password login from %s: %d", remoteAddr, res.StatusCode)
	}
	var out struct {
		TOTPRequired bool   `json:"totp_required"`
		ChallengeID  string `json:"challenge_id"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	return out.TOTPRequired, out.ChallengeID, res.Cookies()
}

func hasSessionCookie(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		if c.Name == "lattice_session" && c.Value != "" {
			return true
		}
	}
	return false
}

func TestTwoFactorFullLifecycle(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	// --- enroll ---
	res := doJSON(t, handler, http.MethodPost, "/api/2fa/totp/enroll", "{}", cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", res.StatusCode)
	}
	var enroll struct {
		Secret        string   `json:"secret"`
		OTPAuthURI    string   `json:"otpauth_uri"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	json.NewDecoder(res.Body).Decode(&enroll)
	res.Body.Close()
	if enroll.Secret == "" || len(enroll.RecoveryCodes) != 10 || enroll.OTPAuthURI == "" {
		t.Fatalf("bad enroll payload: %+v", enroll)
	}

	// before activation, login must NOT require 2FA and SHOULD set a session
	req2fa, _, loginCookies := passwordLogin(t, handler, "198.51.100.1:1000")
	if req2fa || !hasSessionCookie(loginCookies) {
		t.Fatal("login must not require 2FA before activation")
	}

	// --- activate with a valid code ---
	code, _ := auth.TOTPCodeAt(enroll.Secret, time.Now().UTC())
	res = doJSON(t, handler, http.MethodPost, "/api/2fa/totp/activate", `{"code":"`+code+`"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("activate: %d", res.StatusCode)
	}
	res.Body.Close()

	// --- password step now yields a challenge, NOT a session ---
	req2fa, challengeID, loginCookies := passwordLogin(t, handler, "198.51.100.2:1000")
	if !req2fa || challengeID == "" {
		t.Fatal("expected totp_required challenge after activation")
	}
	if hasSessionCookie(loginCookies) {
		t.Fatal("password step must not set a session cookie for a 2FA user")
	}

	// wrong code is rejected but does NOT consume the challenge
	res = doLoginFrom(t, handler, "/api/login/totp", `{"challenge_id":"`+challengeID+`","code":"000000"}`, "198.51.100.2:1000")
	if res.StatusCode == http.StatusOK {
		t.Fatal("wrong totp code must be rejected")
	}
	res.Body.Close()

	// correct code completes login on the same (still-valid) challenge
	code, _ = auth.TOTPCodeAt(enroll.Secret, time.Now().UTC())
	res = doLoginFrom(t, handler, "/api/login/totp", `{"challenge_id":"`+challengeID+`","code":"`+code+`"}`, "198.51.100.2:1000")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("totp login: %d", res.StatusCode)
	}
	if !hasSessionCookie(res.Cookies()) {
		t.Fatal("successful 2FA login must set a session cookie")
	}
	res.Body.Close()

	// challenge is single-use: replaying it must fail
	res = doLoginFrom(t, handler, "/api/login/totp", `{"challenge_id":"`+challengeID+`","code":"`+code+`"}`, "198.51.100.2:1000")
	if res.StatusCode == http.StatusOK {
		t.Fatal("a consumed challenge must not be reusable")
	}
	res.Body.Close()

	// --- recovery code path ---
	_, challengeR, _ := passwordLogin(t, handler, "198.51.100.3:1000")
	res = doLoginFrom(t, handler, "/api/login/totp", `{"challenge_id":"`+challengeR+`","recovery_code":"`+enroll.RecoveryCodes[0]+`"}`, "198.51.100.3:1000")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("recovery login: %d", res.StatusCode)
	}
	if !hasSessionCookie(res.Cookies()) {
		t.Fatal("recovery login must set a session cookie")
	}
	res.Body.Close()

	// the same recovery code must not work twice
	_, challengeR2, _ := passwordLogin(t, handler, "198.51.100.4:1000")
	res = doLoginFrom(t, handler, "/api/login/totp", `{"challenge_id":"`+challengeR2+`","recovery_code":"`+enroll.RecoveryCodes[0]+`"}`, "198.51.100.4:1000")
	if res.StatusCode == http.StatusOK {
		t.Fatal("a used recovery code must not be accepted again")
	}
	res.Body.Close()

	// --- IP binding: a challenge from one IP cannot be redeemed from another ---
	_, challengeIP, _ := passwordLogin(t, handler, "198.51.100.5:1000")
	code, _ = auth.TOTPCodeAt(enroll.Secret, time.Now().UTC())
	res = doLoginFrom(t, handler, "/api/login/totp", `{"challenge_id":"`+challengeIP+`","code":"`+code+`"}`, "203.0.113.9:1000")
	if res.StatusCode == http.StatusOK {
		t.Fatal("a challenge must not be redeemable from a different client IP")
	}
	res.Body.Close()

	// --- a PAT (bearer) must not be able to manage 2FA ---
	pat := createPAT(t, handler, cookies, csrf, []string{"node:read"}, nil)
	res = doBearerJSON(t, handler, http.MethodPost, "/api/2fa/totp/disable", `{"code":"x"}`, pat)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("bearer must be forbidden from 2FA management, got %d", res.StatusCode)
	}
	res.Body.Close()

	// --- disable 2FA with a valid code ---
	code, _ = auth.TOTPCodeAt(enroll.Secret, time.Now().UTC())
	res = doJSON(t, handler, http.MethodPost, "/api/2fa/totp/disable", `{"code":"`+code+`"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("disable: %d", res.StatusCode)
	}
	res.Body.Close()

	// after disable, login no longer requires 2FA
	req2fa, _, loginCookies = passwordLogin(t, handler, "198.51.100.6:1000")
	if req2fa || !hasSessionCookie(loginCookies) {
		t.Fatal("after disable, login must not require 2FA")
	}
}

// TestTwoFactorPerUserBruteForceLockout proves the second-factor guess budget is
// bounded PER USER, not per source IP: rotating the client IP on every attempt
// must NOT widen the budget. After the per-user burst is spent, further guesses
// are rejected with 429 regardless of source address.
func TestTwoFactorPerUserBruteForceLockout(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	res := doJSON(t, handler, http.MethodPost, "/api/2fa/totp/enroll", "{}", cookies, csrf)
	var enroll struct {
		Secret string `json:"secret"`
	}
	json.NewDecoder(res.Body).Decode(&enroll)
	res.Body.Close()
	code, _ := auth.TOTPCodeAt(enroll.Secret, time.Now().UTC())
	res = doJSON(t, handler, http.MethodPost, "/api/2fa/totp/activate", `{"code":"`+code+`"}`, cookies, csrf)
	res.Body.Close()

	lockedAt := -1
	for i := 0; i < 9; i++ {
		ip := fmt.Sprintf("198.51.100.%d:1000", 20+i) // a fresh source IP each time
		_, challengeID, _ := passwordLogin(t, handler, ip)
		if challengeID == "" {
			t.Fatalf("attempt %d: expected a challenge", i)
		}
		res := doLoginFrom(t, handler, "/api/login/totp", `{"challenge_id":"`+challengeID+`","code":"000000"}`, ip)
		status := res.StatusCode
		res.Body.Close()
		if status == http.StatusTooManyRequests {
			lockedAt = i
			break
		}
		if status != http.StatusUnauthorized {
			t.Fatalf("attempt %d from %s: want 401, got %d", i, ip, status)
		}
	}
	if lockedAt < 0 {
		t.Fatal("per-user 2FA limiter never engaged despite rotating source IPs (distributed brute force would succeed)")
	}
	if lockedAt > 6 {
		t.Fatalf("per-user lockout too loose: engaged only at attempt %d", lockedAt)
	}
}

func TestRequireTOTPPolicyGatesInteractiveSessionsUntilEnrollment(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, RequireTOTP: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	me := doJSON(t, handler, http.MethodGet, "/api/me", "", cookies, csrf)
	defer me.Body.Close()
	var principal struct {
		TOTPEnabled        bool `json:"totp_enabled"`
		MFARequired        bool `json:"mfa_required"`
		TOTPPolicyRequired bool `json:"totp_policy_required"`
	}
	if err := json.NewDecoder(me.Body).Decode(&principal); err != nil {
		t.Fatal(err)
	}
	if principal.TOTPEnabled || !principal.MFARequired || !principal.TOTPPolicyRequired {
		t.Fatalf("policy state not exposed on /api/me: %+v", principal)
	}

	denied := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, csrf)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("non-setup API should be gated before TOTP activation, got %d", denied.StatusCode)
	}
	var deniedBody model.APIErrorResponse
	if err := json.NewDecoder(denied.Body).Decode(&deniedBody); err != nil {
		t.Fatal(err)
	}
	if deniedBody.Error.Code != model.APIErrorMFARequired {
		t.Fatalf("gate code = %q, want %q", deniedBody.Error.Code, model.APIErrorMFARequired)
	}
	foundAudit := false
	for _, ev := range st.AuditEvents() {
		if ev.Action == "GET /api/nodes" && ev.Scope == "mfa:required" && ev.Decision == "deny" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("missing mfa_required deny audit: %+v", st.AuditEvents())
	}

	enroll := doJSON(t, handler, http.MethodPost, "/api/2fa/totp/enroll", "{}", cookies, csrf)
	var enrollment struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(enroll.Body).Decode(&enrollment); err != nil {
		t.Fatal(err)
	}
	enroll.Body.Close()
	if enroll.StatusCode != http.StatusOK || enrollment.Secret == "" {
		t.Fatalf("policy must allow enrollment: status=%d enrollment=%+v", enroll.StatusCode, enrollment)
	}
	code, _ := auth.TOTPCodeAt(enrollment.Secret, time.Now().UTC())
	activate := doJSON(t, handler, http.MethodPost, "/api/2fa/totp/activate", `{"code":"`+code+`"}`, cookies, csrf)
	activate.Body.Close()
	if activate.StatusCode != http.StatusOK {
		t.Fatalf("policy must allow activation: %d", activate.StatusCode)
	}

	allowed := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, csrf)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("activated TOTP session should pass policy gate, got %d", allowed.StatusCode)
	}
	me = doJSON(t, handler, http.MethodGet, "/api/me", "", cookies, csrf)
	defer me.Body.Close()
	principal = struct {
		TOTPEnabled        bool `json:"totp_enabled"`
		MFARequired        bool `json:"mfa_required"`
		TOTPPolicyRequired bool `json:"totp_policy_required"`
	}{}
	if err := json.NewDecoder(me.Body).Decode(&principal); err != nil {
		t.Fatal(err)
	}
	if !principal.TOTPEnabled || principal.MFARequired || !principal.TOTPPolicyRequired {
		t.Fatalf("post-activation policy state not exposed correctly: %+v", principal)
	}
}

func TestRequireTOTPPolicyDoesNotGateBearerTokens(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, RequireTOTP: true})
	if err != nil {
		t.Fatal(err)
	}
	user, ok := st.UserByUsername("admin")
	if !ok {
		t.Fatal("admin user missing")
	}
	secret := "automation-token-secret"
	hash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertToken(model.Token{
		ID:        "tok_test",
		Name:      "automation",
		TokenHash: hash,
		ActorID:   user.ID,
		Scopes:    []string{"node:read"},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	res := doBearerJSON(t, srv.Handler(), http.MethodGet, "/api/nodes", "", auth.FormatToken("tok_test", secret))
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("bearer token should not be gated by interactive TOTP policy, got %d", res.StatusCode)
	}
}
