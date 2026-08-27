package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type fakeProvider struct{ records []ddns.Record }

func (f *fakeProvider) Kind() string { return "fake" }
func (f *fakeProvider) SetRecord(ctx context.Context, r ddns.Record) error {
	f.records = append(f.records, r)
	return nil
}

func newDDNSServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), st
}

func TestDDNSCreateListHidesSecret(t *testing.T) {
	_, handler, _ := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"cf","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"super-secret","enable_ipv4":true}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}
	list := doJSON(t, handler, http.MethodGet, "/api/ddns", "", cookies, "")
	defer list.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(list.Body)
	if bytes.Contains(buf.Bytes(), []byte("super-secret")) || bytes.Contains(buf.Bytes(), []byte("cf_api_token")) {
		t.Fatalf("ddns list leaked credential: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"has_credential":true`)) {
		t.Fatalf("expected has_credential flag: %s", buf.String())
	}
}

func TestDDNSCreateValidatesProviderConfig(t *testing.T) {
	_, handler, _ := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	// cloudflare without token must be rejected by eager provider construction.
	res := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"bad","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"enable_ipv4":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for cloudflare without token, got %d", res.StatusCode)
	}
}

func TestDDNSRunUsesProviderAndRecordsIP(t *testing.T) {
	srv, handler, st := newDDNSServer(t)
	fp := &fakeProvider{}
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) { return fp, nil }
	st.UpsertNode(model.Node{ID: "n1", PublicIP: "203.0.113.7"})

	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"x","node_id":"n1","provider":"webhook","webhook_url":"https://example.com/h","domains":["a.example.com"],"enable_ipv4":true}`, cookies, csrf)
	defer create.Body.Close()
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&created)

	run := doJSON(t, handler, http.MethodPost, "/api/ddns/run", `{"id":"`+created.ID+`"}`, cookies, csrf)
	defer run.Body.Close()
	if run.StatusCode != http.StatusOK {
		t.Fatalf("run failed: %d", run.StatusCode)
	}
	assertResponseAuditCorrelation(t, st, run, "ddns.run", "ddns:admin")
	if len(fp.records) != 1 || fp.records[0].IP != "203.0.113.7" || fp.records[0].Type != "A" {
		t.Fatalf("provider not called correctly: %+v", fp.records)
	}
	// status persisted
	list := doJSON(t, handler, http.MethodGet, "/api/ddns", "", cookies, "")
	defer list.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(list.Body)
	if !bytes.Contains(buf.Bytes(), []byte("203.0.113.7")) {
		t.Fatalf("expected last_ipv4 recorded: %s", buf.String())
	}
}

func TestDDNSDelete(t *testing.T) {
	_, handler, _ := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"d","node_id":"n1","provider":"webhook","webhook_url":"https://example.com/h","domains":["a.example.com"]}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	create.Body.Close()
	del := doJSON(t, handler, http.MethodPost, "/api/ddns/delete", `{"id":"`+created.ID+`"}`, cookies, csrf)
	del.Body.Close()
	list := doJSON(t, handler, http.MethodGet, "/api/ddns", "", cookies, "")
	defer list.Body.Close()
	var views []map[string]any
	json.NewDecoder(list.Body).Decode(&views)
	if len(views) != 0 {
		t.Fatalf("expected no profiles after delete, got %d", len(views))
	}
}

// A PAT lacking ddns:admin must be denied the DDNS API.
func TestDDNSRequiresScope(t *testing.T) {
	_, handler, _ := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	mk := doJSON(t, handler, http.MethodPost, "/api/tokens", `{"name":"ro","scopes":["node:read"]}`, cookies, csrf)
	var tok struct {
		Token string `json:"token"`
	}
	json.NewDecoder(mk.Body).Decode(&tok)
	mk.Body.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/ddns", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("node:read token must be forbidden on ddns, got %d", rec.Result().StatusCode)
	}
}

// TestDDNSUpdateKeepsIDAndCredential covers editing an existing profile.
//
// The handler used to overwrite req.ID with a freshly minted one on every
// POST, so a profile could be created and then never changed: re-submitting it
// produced a duplicate, and fixing a typo meant delete-and-recreate. An id in
// the body now means "edit this one". The credential needs its own rule,
// because the list view redacts it: a blank token on an edit cannot mean
// "clear it", since the client never had the value to send back.
func TestDDNSUpdateKeepsIDAndCredential(t *testing.T) {
	_, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)

	create := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"cf","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"first-secret","enable_ipv4":true,"ttl":60}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create: %d", create.StatusCode)
	}
	var made struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&made); err != nil {
		t.Fatal(err)
	}

	// Record a run result so the edit can be shown not to clobber it.
	stored, ok := st.DDNSProfile(made.ID)
	if !ok {
		t.Fatal("profile missing after create")
	}
	stored.LastIPv4 = "203.0.113.9"
	if err := st.UpsertDDNSProfile(stored); err != nil {
		t.Fatal(err)
	}

	// Edit: new name and domain, no credential in the body.
	upd := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"id":"`+made.ID+`","name":"cf-renamed","node_id":"n1","provider":"cloudflare","domains":["b.example.com"],"enable_ipv4":true,"ttl":120}`, cookies, csrf)
	defer upd.Body.Close()
	if upd.StatusCode != http.StatusOK {
		t.Fatalf("update: %d", upd.StatusCode)
	}

	if all := st.DDNSProfiles(); len(all) != 1 {
		t.Fatalf("edit created a duplicate: %d profiles", len(all))
	}
	got, ok := st.DDNSProfile(made.ID)
	if !ok {
		t.Fatal("id changed on update")
	}
	if got.Name != "cf-renamed" || got.TTL != 120 || len(got.Domains) != 1 || got.Domains[0] != "b.example.com" {
		t.Fatalf("edit did not apply: %+v", got)
	}
	if got.CFAPIToken != "first-secret" {
		t.Fatalf("blank credential wiped the stored token: %q", got.CFAPIToken)
	}
	if got.LastIPv4 != "203.0.113.9" {
		t.Fatalf("edit clobbered run status: %q", got.LastIPv4)
	}

	// A non-empty credential replaces the stored one.
	rot := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"id":"`+made.ID+`","name":"cf-renamed","node_id":"n1","provider":"cloudflare","domains":["b.example.com"],"cf_api_token":"second-secret","enable_ipv4":true,"ttl":120}`, cookies, csrf)
	defer rot.Body.Close()
	if rot.StatusCode != http.StatusOK {
		t.Fatalf("rotate: %d", rot.StatusCode)
	}
	if got, _ := st.DDNSProfile(made.ID); got.CFAPIToken != "second-secret" {
		t.Fatalf("credential rotation ignored: %q", got.CFAPIToken)
	}

	// An unknown id is a miss, not a silent create.
	miss := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"id":"ddns_nope","name":"x","node_id":"n1","provider":"cloudflare","domains":["c.example.com"],"cf_api_token":"t","enable_ipv4":true}`, cookies, csrf)
	defer miss.Body.Close()
	if miss.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: got %d want 404", miss.StatusCode)
	}
	if all := st.DDNSProfiles(); len(all) != 1 {
		t.Fatalf("unknown id created a profile: %d", len(all))
	}
}
