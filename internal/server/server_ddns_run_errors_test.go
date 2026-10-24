package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/ddns/cffake"
)

// cfRefusal is how Cloudflare answers a revoked token, with the fields it
// adds to an error that the operator does not need.
const cfRefusal = `{"success":false,"errors":[
	{"code":10000,"message":"Authentication error","documentation_url":"https://developers.cloudflare.com/raw-marker"},
	{"code":9109,"message":"Invalid access token","error_chain":[{"code":1,"message":"chain-marker"}]}
],"messages":["messages-marker"],"result":null}`

// refusingCloudflare points every Cloudflare profile at a server that
// answers each request with status 403 and cfRefusal.
func refusingCloudflare(t *testing.T, srv *Server) {
	t.Helper()
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(cfRefusal))
	}))
	t.Cleanup(cf.Close)
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		prov, err := ddns.NewProvider(p, cf.Client())
		if c, ok := prov.(*ddns.Cloudflare); ok {
			c.BaseURL = cf.URL
		}
		return prov, err
	}
}

// seedAddressProfile stores an address profile for home.example.com on n1,
// with the node's public IPv4, without the save handler's checks.
func seedAddressProfile(t *testing.T, srv *Server, profile model.DDNSProfile) model.DDNSProfile {
	t.Helper()
	if err := srv.store.UpsertNode(model.Node{ID: "n1", Name: "home", PublicIP: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	if profile.ID == "" {
		profile.ID = "ddns_home"
	}
	profile.Name, profile.NodeID = "home", "n1"
	profile.Domains = []string{"home.example.com"}
	profile.EnableIPv4 = true
	profile.CommentMode = model.DDNSCommentNone
	profile.CreatedAt = time.Now().UTC()
	if err := srv.store.UpsertDDNSProfile(profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

// runNowError presses "Run now" and returns the status and the error body.
func runNowError(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, id string) (int, model.APIError) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/ddns/run", `{"id":"`+id+`"}`, cookies, csrf)
	defer res.Body.Close()
	var out model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("run now %d: %v", res.StatusCode, err)
	}
	return res.StatusCode, out.Error
}

// A run Cloudflare refuses answers 502 with Cloudflare's codes and messages,
// not "upstream service error", and the profile stores the same text. No
// other field of the reply reaches either, and neither does the token.
func TestDDNSRunNowQuotesACloudflareRefusal(t *testing.T) {
	srv, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	refusingCloudflare(t, srv)
	made := seedAddressProfile(t, srv, model.DDNSProfile{Provider: model.DDNSProviderCloudflare, CFAPIToken: "secret-cf-token"})

	status, apiErr := runNowError(t, handler, cookies, csrf, made.ID)
	const want = `A home.example.com: cloudflare: api error (status 403): [{"code":10000,"message":"Authentication error"},{"code":9109,"message":"Invalid access token"}]`
	if status != http.StatusBadGateway || apiErr.Code != model.APIErrorBadGateway || apiErr.Message != want {
		t.Fatalf("run now: %d %s %q\nwant 502 %s %q", status, apiErr.Code, apiErr.Message, model.APIErrorBadGateway, want)
	}
	for _, leak := range []string{"raw-marker", "chain-marker", "messages-marker", "documentation_url", "secret-cf-token"} {
		if strings.Contains(apiErr.Message, leak) {
			t.Fatalf("the answer carries %q: %s", leak, apiErr.Message)
		}
	}
	if got, _ := st.DDNSProfile(made.ID); got.LastError != want {
		t.Fatalf("stored reason %q, want the answer's %q", got.LastError, want)
	}
}

// A record in the way is a conflict the operator resolves in Cloudflare: 409
// with the sentence naming it, which the profile stores too.
func TestDDNSRunNowConflictIs409(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	fake.Seed(cffake.Record{Type: "CNAME", Name: "home.example.com", Content: "edge.example.net", TTL: 60})
	made := seedAddressProfile(t, srv, model.DDNSProfile{Provider: model.DDNSProviderCloudflare, CFAPIToken: "t"})

	status, apiErr := runNowError(t, handler, cookies, csrf, made.ID)
	const want = "home.example.com already has a CNAME record pointing to edge.example.net; a name cannot hold both. Remove that record in Cloudflare or use another name."
	if status != http.StatusConflict || apiErr.Message != want {
		t.Fatalf("run now: %d %q, want 409 %q", status, apiErr.Message, want)
	}
	if got, _ := st.DDNSProfile(made.ID); got.LastError != want {
		t.Fatalf("stored reason %q, want the answer's %q", got.LastError, want)
	}
}

// A profile its provider cannot be built from (stored by another path than
// the save handler, which refuses it) answers 422 naming the setting. The run
// is recorded like any other, so the profile shows the same reason and the
// sweep waits an interval before trying again.
func TestDDNSRunNowNamesAMissingSetting(t *testing.T) {
	srv, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	clock := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	serverClock(t, srv).set(clock)
	made := seedAddressProfile(t, srv, model.DDNSProfile{Provider: model.DDNSProviderCloudflare})

	status, apiErr := runNowError(t, handler, cookies, csrf, made.ID)
	const want = "cloudflare: cf_api_token is required"
	if status != http.StatusUnprocessableEntity || apiErr.Message != want {
		t.Fatalf("run now: %d %q, want 422 %q", status, apiErr.Message, want)
	}
	got, _ := st.DDNSProfile(made.ID)
	if got.LastError != want || !got.LastRunAt.Equal(clock) {
		t.Fatalf("the run was not recorded: last error %q at %v", got.LastError, got.LastRunAt)
	}
	if !auditMetadataSeen(st, "ddns.run", "ok", "false") {
		t.Fatal("the failed run was not audited")
	}
}

// scriptedDDNS fails each record type with the error given for it.
type scriptedDDNS map[string]error

func (scriptedDDNS) Kind() string { return "scripted" }
func (s scriptedDDNS) SetRecord(_ context.Context, r ddns.Record) error {
	return s[r.Type]
}

// A failure that never got an answer from the provider keeps the masked 502,
// and so does one where any record failed that way, even when another
// record's failure could be shown. The profile still records the run.
func TestDDNSRunNowMasksAnInternalFailure(t *testing.T) {
	const detail = `Post "https://hook.internal/?token=leak-marker": dial tcp 10.9.8.7:443: connect: connection refused`
	conflict := &ddns.ConflictError{Name: "home.example.com", Type: "A", Existing: []ddns.ExistingRecord{{Type: "CNAME", Content: "edge.example.net"}}}
	cases := map[string]scriptedDDNS{
		"transport only":         {"A": errors.New(detail)},
		"conflict and transport": {"A": conflict, "AAAA": errors.New(detail)},
	}
	for name, prov := range cases {
		t.Run(name, func(t *testing.T) {
			srv, handler, st := newDDNSServer(t)
			cookies, csrf := loginSession(t, handler)
			srv.ddnsProvider = func(model.DDNSProfile) (ddns.Provider, error) { return prov, nil }
			made := seedAddressProfile(t, srv, model.DDNSProfile{Provider: model.DDNSProviderWebhook, WebhookURL: "https://hook.internal/", EnableIPv6: true})
			if err := srv.store.UpsertNode(model.Node{ID: "n1", PublicIP: "203.0.113.10", PublicIPv6: "2001:db8::10"}); err != nil {
				t.Fatal(err)
			}

			status, apiErr := runNowError(t, handler, cookies, csrf, made.ID)
			if status != http.StatusBadGateway || apiErr.Message != "upstream service error" {
				t.Fatalf("run now: %d %q, want 502 %q", status, apiErr.Message, "upstream service error")
			}
			if got, _ := st.DDNSProfile(made.ID); !strings.Contains(got.LastError, "connection refused") {
				t.Fatalf("the run was not recorded: %q", got.LastError)
			}
		})
	}
}

// "Publish" on a DNS deployment's hostname goes through the same answer: a
// Cloudflare refusal is quoted, and the deployment stores the same text.
func TestDNSPublishQuotesACloudflareRefusal(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	refusingCloudflare(t, srv)
	if err := st.UpsertDNSDeployment(model.DNSDeployment{
		ID: "dns_home", Name: "home dns", NodeID: "n1", Engine: model.DNSEngineCoreDNS,
		Hostname: "dns.example.com", PublishIPv4: true, CFAPIToken: "secret-cf-token",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	res := doJSON(t, handler, http.MethodPost, "/api/dns/publish", `{"id":"dns_home"}`, cookies, csrf)
	defer res.Body.Close()
	var out model.APIErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	const want = `A dns.example.com: cloudflare: api error (status 403): [{"code":10000,"message":"Authentication error"},{"code":9109,"message":"Invalid access token"}]`
	if res.StatusCode != http.StatusBadGateway || out.Error.Message != want {
		t.Fatalf("publish: %d %q, want 502 %q", res.StatusCode, out.Error.Message, want)
	}
	if dep, _ := st.DNSDeployment("dns_home"); dep.LastPublishError != want || dep.LastIPv4 != "" {
		t.Fatalf("stored outcome: error %q ipv4 %q", dep.LastPublishError, dep.LastIPv4)
	}
}
