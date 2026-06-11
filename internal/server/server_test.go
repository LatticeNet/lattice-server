package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestLoginAndCSRFProtectedEndpoint(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	body := bytes.NewBufferString(`{"username":"admin","password":"correct horse battery staple"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", body)
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp := httptest.NewRecorder()
	handler.ServeHTTP(loginResp, loginReq)
	resp := loginResp.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	if login.CSRF == "" {
		t.Fatal("missing csrf token")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/nodes/enroll-token", bytes.NewBufferString(`{"node_id":"n1","name":"N1"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}
	deniedResp := httptest.NewRecorder()
	handler.ServeHTTP(deniedResp, req)
	denied := deniedResp.Result()
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("expected csrf denial, got %d", denied.StatusCode)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/nodes/enroll-token", bytes.NewBufferString(`{"node_id":"n1","name":"N1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Lattice-CSRF", login.CSRF)
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}
	allowedResp := httptest.NewRecorder()
	handler.ServeHTTP(allowedResp, req)
	allowed := allowedResp.Result()
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("expected enroll success, got %d", allowed.StatusCode)
	}
}

func TestCleanObjectPathRejectsTraversal(t *testing.T) {
	for _, value := range []string{"../secret", "safe/../../secret", `safe\..\secret`} {
		if _, err := cleanObjectPath(value); err == nil {
			t.Fatalf("expected traversal path %q to fail", value)
		}
	}
	clean, err := cleanObjectPath("site/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if clean != "site/index.html" {
		t.Fatalf("unexpected clean path %q", clean)
	}
}
