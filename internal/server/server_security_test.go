package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
)

const testAdminPass = "correct horse battery staple"

// loginSession logs in as admin and returns the cookies plus CSRF token.
func loginSession(t *testing.T, handler http.Handler) ([]*http.Cookie, string) {
	t.Helper()
	body := bytes.NewBufferString(`{"username":"admin","password":"` + testAdminPass + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", res.StatusCode)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	return res.Cookies(), out.CSRF
}

func newTestServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), st
}

func doJSON(t *testing.T, handler http.Handler, method, path, body string, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-Lattice-CSRF", csrf)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

// Admin (scope "*") can create a task: the previously-buggy static:write gate
// is gone, so task:run alone (via the route) is sufficient.
func TestTaskCreateNoLongerRequiresStaticWrite(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["n1"],"interpreter":"sh","script":"echo hi"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("task create should succeed for admin, got %d", res.StatusCode)
	}
}

func TestKVRejectsSlashInKey(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/kv",
		`{"bucket":"default","key":"a/b","value":"x"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("slash in key should be rejected, got %d", res.StatusCode)
	}
}

func TestStaticRejectsSlashInBucket(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/static",
		`{"bucket":"a/b","path":"index.html","content":"x"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("slash in bucket should be rejected, got %d", res.StatusCode)
	}
}

// A session minted against one store must remain valid when a fresh server is
// constructed over the same store (i.e. across a restart).
func TestSessionSurvivesServerRestart(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv1, _ := New(Options{Store: st, AdminPassword: testAdminPass})
	h1 := srv1.Handler()
	cookies, _ := loginSession(t, h1)

	srv2, _ := New(Options{Store: st, AdminPassword: testAdminPass})
	h2 := srv2.Handler()
	res := doJSON(t, h2, http.MethodGet, "/api/me", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session should survive restart, got %d", res.StatusCode)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/logout", "{}", cookies, csrf)
	res.Body.Close()
	after := doJSON(t, handler, http.MethodGet, "/api/me", "", cookies, "")
	defer after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session should be dead after logout, got %d", after.StatusCode)
	}
}

// Full PAT lifecycle: create -> use via bearer -> revoke -> rejected.
func TestPATCreateUseAndRevoke(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/tokens",
		`{"name":"ci","scopes":["node:read"]}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("token create failed: %d", create.StatusCode)
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	if created.Token == "" {
		t.Fatal("expected token credential")
	}

	// Use the bearer token on a node:read endpoint.
	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("bearer token should access node:read, got %d", rec.Result().StatusCode)
	}

	// Bearer must be denied a scope it lacks (task:run).
	req = httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(`{"targets":["n"],"script":"x"}`))
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("bearer without task:run should be forbidden, got %d", rec.Result().StatusCode)
	}

	// Revoke, then the same token must be rejected.
	rev := doJSON(t, handler, http.MethodPost, "/api/tokens/revoke",
		`{"token_id":"`+created.ID+`"}`, cookies, csrf)
	rev.Body.Close()
	req = httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token must be rejected, got %d", rec.Result().StatusCode)
	}
}

// The token list must never expose secrets or hashes.
func TestTokenListHidesHash(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	doJSON(t, handler, http.MethodPost, "/api/tokens", `{"name":"x","scopes":["node:read"]}`, cookies, csrf).Body.Close()
	res := doJSON(t, handler, http.MethodGet, "/api/tokens", "", cookies, "")
	defer res.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(res.Body)
	if bytes.Contains(buf.Bytes(), []byte("token_hash")) || bytes.Contains(buf.Bytes(), []byte("pbkdf2")) {
		t.Fatalf("token list leaked secret material: %s", buf.String())
	}
}

func TestLoginRateLimited(t *testing.T) {
	handler, _ := newTestServer(t)
	limited := false
	for i := 0; i < 20; i++ {
		res := doJSON(t, handler, http.MethodPost, "/api/login", `{"username":"admin","password":"wrong"}`, nil, "")
		code := res.StatusCode
		res.Body.Close()
		if code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("expected login to be rate limited after repeated attempts")
	}
}
