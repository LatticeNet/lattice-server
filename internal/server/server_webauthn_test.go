package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Passkey (WebAuthn) HTTP-level tests. Full begin→finish ceremonies are driven
// by a virtual authenticator (github.com/descope/virtualwebauthn, TEST-ONLY) so
// each flow exercises real CBOR/COSE attestation and assertion parsing against
// the go-webauthn verifier — not a mock.

const (
	testWebAuthnOrigin = "https://lattice.test"
	testWebAuthnRPID   = "lattice.test"
)

func webAuthnRP() virtualwebauthn.RelyingParty {
	return virtualwebauthn.RelyingParty{ID: testWebAuthnRPID, Name: "Lattice", Origin: testWebAuthnOrigin}
}

// doPasskeyRegister runs a full registration ceremony and returns the finish
// response (unread) so the caller can assert on status/body.
func doPasskeyRegister(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, authr *virtualwebauthn.Authenticator, cred virtualwebauthn.Credential, name, grant string) *http.Response {
	t.Helper()
	beginBody := "{}"
	if grant != "" {
		beginBody = `{"step_up_grant":"` + grant + `"}`
	}
	res := doJSON(t, handler, http.MethodPost, "/api/security/webauthn/register/begin", beginBody, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		return res
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	if err := json.Unmarshal(body, &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	opts, err := virtualwebauthn.ParseAttestationOptions(string(body))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	attestation := virtualwebauthn.CreateAttestationResponse(webAuthnRP(), *authr, cred, *opts)
	finish := mustJSON(t, map[string]any{
		"challenge_id":  begin.ChallengeID,
		"name":          name,
		"credential":    json.RawMessage(attestation),
		"step_up_grant": grant,
	})
	return doJSON(t, handler, http.MethodPost, "/api/security/webauthn/register/finish", string(finish), cookies, csrf)
}

// doPasskeyLoginWithRP runs a discoverable login using a caller-supplied relying
// party (so tests can inject a bad origin/RPID). Returns the finish response.
func doPasskeyLoginWithRP(t *testing.T, handler http.Handler, remoteAddr string, rp virtualwebauthn.RelyingParty, authr *virtualwebauthn.Authenticator, cred virtualwebauthn.Credential) *http.Response {
	t.Helper()
	res := doLoginFrom(t, handler, "/api/auth/webauthn/login/begin", "{}", remoteAddr)
	if res.StatusCode != http.StatusOK {
		return res
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	if err := json.Unmarshal(body, &begin); err != nil {
		t.Fatalf("decode login begin: %v", err)
	}
	opts, err := virtualwebauthn.ParseAssertionOptions(string(body))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	assertion := virtualwebauthn.CreateAssertionResponse(rp, *authr, cred, *opts)
	finish := mustJSON(t, map[string]any{
		"challenge_id": begin.ChallengeID,
		"credential":   json.RawMessage(assertion),
	})
	return doLoginFrom(t, handler, "/api/auth/webauthn/login/finish", string(finish), remoteAddr)
}

func adminID(t *testing.T, st *store.Store) string {
	t.Helper()
	u, ok := st.UserByUsername("admin")
	if !ok {
		t.Fatal("admin user missing")
	}
	return u.ID
}

func decodeCredentialID(t *testing.T, res *http.Response) string {
	t.Helper()
	var out struct {
		Credential struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"credential"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode credential: %v", err)
	}
	res.Body.Close()
	return out.Credential.ID
}

func TestWebAuthnRegisterAndLoginRoundTrip(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, testWebAuthnOrigin)
	cookies, csrf := loginSession(t, handler)

	authr := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// --- register ---
	res := doPasskeyRegister(t, handler, cookies, csrf, &authr, cred, "My MacBook", "")
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("register finish: want 200, got %d (%s)", res.StatusCode, b)
	}
	credID := decodeCredentialID(t, res)
	if credID == "" {
		t.Fatal("register returned empty credential id")
	}
	if n := st.CountWebAuthnCredentialsByUser(adminID(t, st)); n != 1 {
		t.Fatalf("expected 1 stored passkey, got %d", n)
	}

	// --- list surfaces it ---
	list := doJSON(t, handler, http.MethodGet, "/api/security/webauthn/credentials", "", cookies, csrf)
	var listOut struct {
		Credentials []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"credentials"`
	}
	json.NewDecoder(list.Body).Decode(&listOut)
	list.Body.Close()
	if len(listOut.Credentials) != 1 || listOut.Credentials[0].Name != "My MacBook" {
		t.Fatalf("list did not surface the registered passkey: %+v", listOut.Credentials)
	}

	// --- usernameless login ---
	authr.Options.UserHandle = []byte(adminID(t, st))
	res = doPasskeyLoginWithRP(t, handler, "203.0.113.5:1000", webAuthnRP(), &authr, cred)
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("passkey login: want 200, got %d (%s)", res.StatusCode, b)
	}
	if !hasSessionCookie(res.Cookies()) {
		t.Fatal("successful passkey login must set a session cookie")
	}
	res.Body.Close()

	// --- rename ---
	rename := doJSON(t, handler, http.MethodPost, "/api/security/webauthn/credentials/rename",
		`{"id":"`+credID+`","name":"Work Laptop"}`, cookies, csrf)
	if rename.StatusCode != http.StatusOK {
		t.Fatalf("rename: %d", rename.StatusCode)
	}
	rename.Body.Close()

	// --- delete (no TOTP enrolled → no step-up required) ---
	del := doJSON(t, handler, http.MethodPost, "/api/security/webauthn/credentials/delete",
		`{"id":"`+credID+`"}`, cookies, csrf)
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", del.StatusCode)
	}
	del.Body.Close()
	if n := st.CountWebAuthnCredentialsByUser(adminID(t, st)); n != 0 {
		t.Fatalf("expected 0 passkeys after delete, got %d", n)
	}
}

func TestWebAuthnLoginRejectsBadOriginRPIDAndReuse(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, testWebAuthnOrigin)
	cookies, csrf := loginSession(t, handler)

	authr := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	if res := doPasskeyRegister(t, handler, cookies, csrf, &authr, cred, "Key", ""); res.StatusCode != http.StatusOK {
		t.Fatalf("register: %d", res.StatusCode)
	}
	authr.Options.UserHandle = []byte(adminID(t, st))

	// Wrong origin: the assertion's clientData origin is not an allowed RP origin.
	badOrigin := virtualwebauthn.RelyingParty{ID: testWebAuthnRPID, Name: "Lattice", Origin: "https://evil.example"}
	if res := doPasskeyLoginWithRP(t, handler, "203.0.113.6:1000", badOrigin, &authr, cred); res.StatusCode == http.StatusOK {
		t.Fatal("login with a mismatched origin must be rejected")
	} else {
		res.Body.Close()
	}

	// Wrong RPID: the authenticator-data RP-ID hash will not match.
	badRPID := virtualwebauthn.RelyingParty{ID: "evil.example", Name: "Lattice", Origin: testWebAuthnOrigin}
	if res := doPasskeyLoginWithRP(t, handler, "203.0.113.7:1000", badRPID, &authr, cred); res.StatusCode == http.StatusOK {
		t.Fatal("login with a mismatched RPID must be rejected")
	} else {
		res.Body.Close()
	}

	// Challenge reuse: capture a valid begin, complete it once, then replay the
	// exact same challenge + assertion — the consumed challenge must be gone.
	res := doLoginFrom(t, handler, "/api/auth/webauthn/login/begin", "{}", "203.0.113.8:1000")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	json.Unmarshal(body, &begin)
	opts, err := virtualwebauthn.ParseAssertionOptions(string(body))
	if err != nil {
		t.Fatal(err)
	}
	assertion := virtualwebauthn.CreateAssertionResponse(webAuthnRP(), authr, cred, *opts)
	finishBody := string(mustJSON(t, map[string]any{"challenge_id": begin.ChallengeID, "credential": json.RawMessage(assertion)}))
	first := doLoginFrom(t, handler, "/api/auth/webauthn/login/finish", finishBody, "203.0.113.8:1000")
	if first.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(first.Body)
		t.Fatalf("first login should succeed: %d (%s)", first.StatusCode, b)
	}
	first.Body.Close()
	replay := doLoginFrom(t, handler, "/api/auth/webauthn/login/finish", finishBody, "203.0.113.8:1000")
	if replay.StatusCode == http.StatusOK {
		t.Fatal("replaying a consumed challenge must fail")
	}
	replay.Body.Close()
}

func TestWebAuthnLoginIPBinding(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, testWebAuthnOrigin)
	cookies, csrf := loginSession(t, handler)
	authr := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	if res := doPasskeyRegister(t, handler, cookies, csrf, &authr, cred, "Key", ""); res.StatusCode != http.StatusOK {
		t.Fatalf("register: %d", res.StatusCode)
	}
	authr.Options.UserHandle = []byte(adminID(t, st))

	// Begin from one IP, finish from another — the challenge is IP-bound.
	res := doLoginFrom(t, handler, "/api/auth/webauthn/login/begin", "{}", "203.0.113.20:1000")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	json.Unmarshal(body, &begin)
	opts, _ := virtualwebauthn.ParseAssertionOptions(string(body))
	assertion := virtualwebauthn.CreateAssertionResponse(webAuthnRP(), authr, cred, *opts)
	finishBody := string(mustJSON(t, map[string]any{"challenge_id": begin.ChallengeID, "credential": json.RawMessage(assertion)}))
	res = doLoginFrom(t, handler, "/api/auth/webauthn/login/finish", finishBody, "198.51.100.99:1000")
	if res.StatusCode == http.StatusOK {
		t.Fatal("a passkey challenge must not be redeemable from a different client IP")
	}
	res.Body.Close()
}

func TestWebAuthnSignCountRegressionWarnsButAllows(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	srv, err := New(Options{
		Store:                   st,
		AdminPassword:           testAdminPass,
		PublicURL:               testWebAuthnOrigin,
		Logger:                  log.New(&logBuf, "", 0),
		DisableRenewalScheduler: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	authr := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	res := doPasskeyRegister(t, handler, cookies, csrf, &authr, cred, "Key", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register: %d", res.StatusCode)
	}
	credID := decodeCredentialID(t, res)
	authr.Options.UserHandle = []byte(adminID(t, st))

	// Simulate a previously-observed non-zero counter, then present a lower one.
	if err := st.TouchWebAuthnCredential(credID, 10, false, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	cred.Counter = 5

	res = doPasskeyLoginWithRP(t, handler, "203.0.113.30:1000", webAuthnRP(), &authr, cred)
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("regressed sign-count login must still succeed (warn-not-fail), got %d (%s)", res.StatusCode, b)
	}
	res.Body.Close()
	if !bytes.Contains(logBuf.Bytes(), []byte("sign-count regression")) {
		t.Fatalf("expected a sign-count regression warning in the log, got: %s", logBuf.String())
	}
}

func TestWebAuthnStepUpGatingOnRegisterAndDelete(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, testWebAuthnOrigin)
	cookies, csrf := loginSession(t, handler)

	// Enroll+activate TOTP and obtain a fresh step-up grant. Now register/delete
	// are gated on step-up. The grant is reusable within its 60s window.
	grant := issueStepUpGrant(t, handler, cookies, csrf)

	// Registration must be refused without a step-up grant once TOTP is enrolled.
	noGrant := doJSON(t, handler, http.MethodPost, "/api/security/webauthn/register/begin", "{}", cookies, csrf)
	if noGrant.StatusCode != http.StatusForbidden {
		t.Fatalf("register begin without step-up: want 403, got %d", noGrant.StatusCode)
	}
	noGrant.Body.Close()

	// With the grant, the full ceremony succeeds.
	authr := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	res := doPasskeyRegister(t, handler, cookies, csrf, &authr, cred, "Key", grant)
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("register with step-up: want 200, got %d (%s)", res.StatusCode, b)
	}
	credID := decodeCredentialID(t, res)
	_ = st

	// Delete must be refused without a step-up grant.
	delNoGrant := doJSON(t, handler, http.MethodPost, "/api/security/webauthn/credentials/delete",
		`{"id":"`+credID+`"}`, cookies, csrf)
	if delNoGrant.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without step-up: want 403, got %d", delNoGrant.StatusCode)
	}
	delNoGrant.Body.Close()

	// With the grant, delete succeeds.
	del := doJSON(t, handler, http.MethodPost, "/api/security/webauthn/credentials/delete",
		`{"id":"`+credID+`","step_up_grant":"`+grant+`"}`, cookies, csrf)
	if del.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(del.Body)
		t.Fatalf("delete with step-up: want 200, got %d (%s)", del.StatusCode, b)
	}
	del.Body.Close()
}

func TestWebAuthnUnavailableWithoutPublicURL(t *testing.T) {
	handler, _ := newTestServer(t) // no PublicURL, no host fallback
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/security/webauthn/register/begin", "{}", cookies, csrf)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("passkeys must be unavailable without an external URL: want 503, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestWebAuthnManagementRejectsBearerTokens(t *testing.T) {
	handler, _ := newTestServerWithPublicURL(t, testWebAuthnOrigin)
	cookies, csrf := loginSession(t, handler)
	pat := createPAT(t, handler, cookies, csrf, []string{"node:read"}, nil)
	res := doBearerJSON(t, handler, http.MethodPost, "/api/security/webauthn/register/begin", "{}", pat)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("bearer PAT must not manage passkeys: want 403, got %d", res.StatusCode)
	}
	res.Body.Close()
}
