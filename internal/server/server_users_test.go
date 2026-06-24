package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// authedPost issues a CSRF+cookie-authenticated POST and returns the recorder.
func authedPost(t *testing.T, h http.Handler, cookies []*http.Cookie, csrf, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Lattice-CSRF", csrf)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func authedGet(t *testing.T, h http.Handler, cookies []*http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUserManagementCRUD(t *testing.T) {
	h, st := newTestServer(t)
	cookies, csrf := loginSession(t, h)

	// Create an SSO-only operator (no password) whose username is their email.
	rec := authedPost(t, h, cookies, csrf, "/api/users", `{"username":"alice@example.com","scopes":["node:read"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "password_hash") {
		t.Fatal("create response leaked password_hash")
	}
	var created userView
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Username != "alice@example.com" || created.HasPassword {
		t.Fatalf("unexpected created view: %+v", created)
	}
	if u, ok := st.UserByUsername("alice@example.com"); !ok || u.PasswordHash != "" {
		t.Fatalf("alice not stored as SSO-only: ok=%v", ok)
	}
	aliceID := created.ID

	// Duplicate username rejected.
	if rec := authedPost(t, h, cookies, csrf, "/api/users", `{"username":"alice@example.com","scopes":[]}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate username: want 409 got %d", rec.Code)
	}

	// Unknown scope rejected.
	if rec := authedPost(t, h, cookies, csrf, "/api/users", `{"username":"bob@example.com","scopes":["bogus:scope"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown scope: want 400 got %d", rec.Code)
	}

	// List never leaks secrets and includes admin + alice.
	rec = authedGet(t, h, cookies, "/api/users")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "password_hash") {
		t.Fatalf("list: %d leaked=%v", rec.Code, strings.Contains(rec.Body.String(), "password_hash"))
	}

	// Scope update bumps SecurityEpoch (revokes the target's sessions).
	before, _ := st.User(aliceID)
	rec = authedPost(t, h, cookies, csrf, "/api/users/update", `{"id":"`+aliceID+`","scopes":["node:admin"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update scopes: %d %s", rec.Code, rec.Body.String())
	}
	after, _ := st.User(aliceID)
	if after.SecurityEpoch <= before.SecurityEpoch {
		t.Fatalf("epoch not bumped on scope change: %d -> %d", before.SecurityEpoch, after.SecurityEpoch)
	}

	// Delete cascades the OIDC identity link.
	if err := st.PutOIDCIdentity(model.OIDCIdentity{ProviderID: "p", Subject: "s", UserID: aliceID, Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	rec = authedPost(t, h, cookies, csrf, "/api/users/delete", `{"id":"`+aliceID+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := st.User(aliceID); ok {
		t.Fatal("user not deleted")
	}
	if _, ok := st.OIDCIdentity("p", "s"); ok {
		t.Fatal("oidc identity not cascaded on delete")
	}
}

func TestUserManagementGuardrails(t *testing.T) {
	h, st := newTestServer(t)
	cookies, csrf := loginSession(t, h)
	admin, ok := st.UserByUsername("admin")
	if !ok {
		t.Fatal("bootstrap admin missing")
	}

	// Cannot delete your own account.
	if rec := authedPost(t, h, cookies, csrf, "/api/users/delete", `{"id":"`+admin.ID+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("self-delete: want 403 got %d %s", rec.Code, rec.Body.String())
	}
	// Cannot remove your own admin (*) scope.
	if rec := authedPost(t, h, cookies, csrf, "/api/users/update", `{"id":"`+admin.ID+`","scopes":["node:read"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("self-de-admin: want 403 got %d %s", rec.Code, rec.Body.String())
	}
	// Admin still has its wildcard scope after the refused edits.
	if cur, _ := st.User(admin.ID); !hasWildcardScope(cur.Scopes) {
		t.Fatal("admin lost its wildcard scope despite refusal")
	}
}
