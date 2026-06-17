package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

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

func TestStaticHandlerCacheHeaders(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:         st,
		AdminPassword: "correct horse battery staple",
		WebFS: fstest.MapFS{
			"index.html":        {Data: []byte("<div id=\"app\"></div>")},
			"theme-init.js":     {Data: []byte("/* theme bootstrap */")},
			"assets/app-abc.js": {Data: []byte("export default 1")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	cases := []struct {
		path string
		want string
	}{
		{"/", "no-cache"},
		{"/login", "no-cache"},
		{"/theme-init.js", "no-cache"},
		{"/assets/app-abc.js", "public, max-age=31536000, immutable"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			res := resp.Result()
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status %d", res.StatusCode)
			}
			if got := res.Header.Get("Cache-Control"); got != tc.want {
				t.Fatalf("Cache-Control = %q, want %q", got, tc.want)
			}
		})
	}
}
