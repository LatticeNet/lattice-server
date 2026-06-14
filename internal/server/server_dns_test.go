package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newDNSServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "n1", Name: "tokyo-1", PublicIP: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "n2", Name: "la-1", PublicIP: "198.51.100.9"}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), st
}

func TestDNSDeploymentCreateListHidesSecret(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"cf_api_token":"super-secret-dns-token",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1","1.1.1.1"]}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}
	var created map[string]any
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created["cf_api_token"] != nil {
		t.Fatalf("create response leaked token field: %+v", created)
	}
	if created["has_credential"] != true {
		t.Fatalf("create response should expose only has_credential: %+v", created)
	}
	if created["listen_port"].(float64) != 53 || created["exposure"] != model.DNSExposureMesh || created["status"] != model.DNSStatusPending {
		t.Fatalf("expected safe defaults in view: %+v", created)
	}

	id := created["id"].(string)
	stored, ok := st.DNSDeployment(id)
	if !ok || stored.CFAPIToken != "super-secret-dns-token" {
		t.Fatalf("token should persist server-side only: ok=%v dep=%+v", ok, stored)
	}
	if len(stored.Zones) != 1 || len(stored.Zones[0].Upstreams) != 1 || stored.Zones[0].Suffix != "." {
		t.Fatalf("zone should be normalized/de-duplicated: %+v", stored.Zones)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/dns/deployments", "", cookies, "")
	defer list.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(list.Body)
	if bytes.Contains(buf.Bytes(), []byte("super-secret-dns-token")) || bytes.Contains(buf.Bytes(), []byte("cf_api_token")) {
		t.Fatalf("dns deployment list leaked credential: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"has_credential":true`)) {
		t.Fatalf("expected has_credential flag: %s", buf.String())
	}
}

func TestDNSDeploymentValidatesConfig(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown engine",
			body: `{"name":"x","node_id":"n1","engine":"bind","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`,
		},
		{
			name: "bad upstream injection",
			body: `{"name":"x","node_id":"n1","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1\nmalicious"]}]}`,
		},
		{
			name: "public hostname without credential",
			body: `{"name":"x","node_id":"n1","hostname":"n1.dns.example.com","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`,
		},
		{
			name: "invalid static record",
			body: `{"name":"x","node_id":"n1","zones":[{"suffix":"mesh.local","mode":"static","records":[{"name":"gw.mesh.local","type":"A","value":"not-ip"}]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", tc.body, cookies, csrf)
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", res.StatusCode)
			}
		})
	}
}

func TestDNSDeploymentUpdatePreservesSecret(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"cf_api_token":"keep-me",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	create.Body.Close()
	update := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"id":"`+created.ID+`",
		"name":"renamed dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"zones":[{"suffix":".","mode":"forward","upstreams":["9.9.9.9"]}]
	}`, cookies, csrf)
	defer update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("update failed: %d", update.StatusCode)
	}
	stored, ok := st.DNSDeployment(created.ID)
	if !ok || stored.CFAPIToken != "keep-me" || stored.Name != "renamed dns" {
		t.Fatalf("update should preserve write-only token: ok=%v dep=%+v", ok, stored)
	}
}

func TestDNSDeploymentRequiresScopeAndAllowlist(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	mk := doJSON(t, handler, http.MethodPost, "/api/tokens", `{"name":"dns-n1","scopes":["dns:admin"],"server_allowlist":["n1"]}`, cookies, csrf)
	var tok struct {
		Token string `json:"token"`
	}
	json.NewDecoder(mk.Body).Decode(&tok)
	mk.Body.Close()

	body := `{"name":"private dns","node_id":"n2","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/dns/deployments", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must be forbidden on n2, got %d", rec.Result().StatusCode)
	}

	okBody := `{"name":"private dns","node_id":" n1 ","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`
	okReq := httptest.NewRequest(http.MethodPost, "/api/dns/deployments", bytes.NewBufferString(okBody))
	okReq.Header.Set("Authorization", "Bearer "+tok.Token)
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	handler.ServeHTTP(okRec, okReq)
	if okRec.Result().StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should accept trimmed n1, got %d", okRec.Result().StatusCode)
	}
}

func TestDNSDeploymentDelete(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	create.Body.Close()

	del := doJSON(t, handler, http.MethodPost, "/api/dns/deployments/delete", `{"id":"`+created.ID+`"}`, cookies, csrf)
	del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", del.StatusCode)
	}
	list := doJSON(t, handler, http.MethodGet, "/api/dns/deployments", "", cookies, "")
	defer list.Body.Close()
	var out struct {
		Deployments []map[string]any `json:"deployments"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Deployments) != 0 {
		t.Fatalf("expected no deployments after delete: %+v", out)
	}
}
