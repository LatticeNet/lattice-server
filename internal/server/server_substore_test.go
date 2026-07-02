package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// fakeSubStore records the requests the companion makes and emulates the upsert
// contract: PATCH /api/sub/:name returns 404 (not found) so the companion falls
// back to POST /api/subs (create).
func TestImportToSubStoreUpserts(t *testing.T) {
	var (
		mu       sync.Mutex
		patchHit bool
		postBody []byte
		envHit   bool
	)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/secret/api/sub/"):
			patchHit = true
			w.WriteHeader(http.StatusNotFound) // force create fallback
		case r.Method == http.MethodPost && r.URL.Path == "/secret/api/subs":
			postBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/secret/api/utils/env":
			envHit = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer fake.Close()
	baseURL := fake.URL + "/secret"

	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pushed, err := srv.importToSubStore(context.Background(), baseURL, "", "")
	if err != nil {
		t.Fatalf("importToSubStore: %v", err)
	}
	if pushed != 0 { // empty store -> no links, but the managed sub is still upserted
		t.Fatalf("expected 0 links from empty store, got %d", pushed)
	}

	// Snapshot under lock, then release BEFORE making further HTTP calls (the
	// fake handler also takes this lock, so holding it across a request deadlocks).
	mu.Lock()
	gotPatch := patchHit
	body := append([]byte(nil), postBody...)
	mu.Unlock()
	if !gotPatch {
		t.Fatalf("expected a PATCH update attempt first")
	}
	if len(body) == 0 {
		t.Fatalf("expected a POST create fallback")
	}
	var sub struct {
		Name    string `json:"name"`
		Source  string `json:"source"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &sub); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if sub.Name != defaultSubStoreSubName || sub.Source != "local" {
		t.Fatalf("unexpected managed sub: %+v", sub)
	}

	// status probe hits /api/utils/env and reports reachable
	code, err := subStoreDo(context.Background(), http.MethodGet, baseURL+"/api/utils/env", nil)
	mu.Lock()
	gotEnv := envHit
	mu.Unlock()
	if err != nil || code != http.StatusOK || !gotEnv {
		t.Fatalf("status probe: code=%d err=%v envHit=%v", code, err, gotEnv)
	}
}

func TestImportToSubStoreRequiresBaseURL(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.importToSubStore(context.Background(), "  ", "", ""); err == nil {
		t.Fatalf("expected error for empty base url")
	}
}

func TestNormalizeSubStoreBaseURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "https remote with secret path", in: " https://store.example.com/secret/ ", want: "https://store.example.com/secret"},
		{name: "localhost http", in: "http://localhost:3001/secret", want: "http://localhost:3001/secret"},
		{name: "loopback http", in: "http://127.0.0.1:3001/a/b/", want: "http://127.0.0.1:3001/a/b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeSubStoreBaseURL(tc.in)
			if err != nil {
				t.Fatalf("normalizeSubStoreBaseURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "relative", in: "/secret"},
		{name: "wrong scheme", in: "ftp://store.example.com/secret"},
		{name: "remote http", in: "http://store.example.com/secret"},
		{name: "credentials", in: "https://user:pass@store.example.com/secret"},
		{name: "missing secret path", in: "https://store.example.com"},
		{name: "root path", in: "https://store.example.com/"},
		{name: "query", in: "https://store.example.com/secret?token=leak"},
		{name: "fragment", in: "https://store.example.com/secret#frag"},
		{name: "dot segment", in: "https://store.example.com/secret/../other"},
		{name: "invalid port", in: "https://store.example.com:70000/secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := normalizeSubStoreBaseURL(tc.in); err == nil {
				t.Fatalf("expected error, got %q", got)
			}
		})
	}
}

func TestSubStoreHandlersRequireGlobalProxyScope(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	baseURL := "http://127.0.0.1:1/secret"
	readRestricted := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, []string{"node-a"})
	status := doBearerJSON(t, handler, http.MethodGet, "/api/substore/status?base_url="+url.QueryEscape(baseURL), "", readRestricted)
	defer status.Body.Close()
	if status.StatusCode != http.StatusForbidden {
		t.Fatalf("restricted proxy:read status = %d, want 403", status.StatusCode)
	}

	adminRestricted := createPAT(t, handler, cookies, csrf, []string{"proxy:admin"}, []string{"node-a"})
	imp := doBearerJSON(t, handler, http.MethodPost, "/api/substore/import", `{"base_url":"`+baseURL+`"}`, adminRestricted)
	defer imp.Body.Close()
	if imp.StatusCode != http.StatusForbidden {
		t.Fatalf("restricted proxy:admin import = %d, want 403", imp.StatusCode)
	}
}

func TestSubStoreHandlersRejectInvalidBaseURL(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)
	status := doBearerJSON(t, handler, http.MethodGet, "/api/substore/status?base_url="+url.QueryEscape("http://store.example.com/secret"), "", readToken)
	defer status.Body.Close()
	if status.StatusCode != http.StatusBadRequest {
		t.Fatalf("remote http status = %d, want 400", status.StatusCode)
	}

	adminToken := createPAT(t, handler, cookies, csrf, []string{"proxy:admin"}, nil)
	imp := doBearerJSON(t, handler, http.MethodPost, "/api/substore/import", `{"base_url":"https://store.example.com"}`, adminToken)
	defer imp.Body.Close()
	if imp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing secret path import = %d, want 400", imp.StatusCode)
	}
}

func TestSubStoreStatusRequiresGET(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	readToken := createPAT(t, handler, cookies, csrf, []string{"proxy:read"}, nil)

	res := doBearerJSON(t, handler, http.MethodPost, "/api/substore/status?base_url="+url.QueryEscape("http://127.0.0.1:1/secret"), "", readToken)
	defer res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", res.StatusCode)
	}
}
