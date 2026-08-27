package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// TestDDNSSweepPublishesOnlyChanges covers the periodic republish.
//
// Profiles used to run only on an operator's button press, so a record went
// stale the moment a residential address changed. The sweep closes that, but it
// must not turn into a rewrite loop: a fleet whose addresses are steady should
// cost nothing at the provider.
func TestDDNSSweepPublishesOnlyChanges(t *testing.T) {
	srv, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)

	if err := st.UpsertNode(model.Node{ID: "n1", PublicIP: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	fake := &fakeProvider{}
	srv.ddnsProvider = func(model.DDNSProfile) (ddns.Provider, error) { return fake, nil }
	// Sweeps are spaced by each profile's interval, so drive the clock rather
	// than calling back to back.
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }
	tick := func() { clock = clock.Add(10 * time.Minute) }

	create := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"cf","node_id":"n1","provider":"webhook","webhook_url":"https://example.com/h","domains":["a.example.com"],"enable_ipv4":true}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create: %d", create.StatusCode)
	}

	// First sweep publishes, because nothing has been published yet.
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("first sweep wrote %d, want 1", n)
	}
	if len(fake.records) != 1 || fake.records[0].IP != "203.0.113.10" {
		t.Fatalf("provider saw %+v", fake.records)
	}

	// Nothing moved, so nothing is written.
	tick()
	if n := srv.sweepDDNSOnce(); n != 0 {
		t.Fatalf("steady sweep wrote %d, want 0", n)
	}
	if len(fake.records) != 1 {
		t.Fatalf("steady sweep hit the provider: %+v", fake.records)
	}

	// The address moves: the record follows it.
	if err := st.UpsertNode(model.Node{ID: "n1", PublicIP: "203.0.113.11"}); err != nil {
		t.Fatal(err)
	}
	tick()
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("changed sweep wrote %d, want 1", n)
	}
	if len(fake.records) != 2 || fake.records[1].IP != "203.0.113.11" {
		t.Fatalf("provider did not follow the address: %+v", fake.records)
	}

	// A profile whose last run failed is retried even though nothing moved,
	// so a corrected credential is picked up without another address change.
	stored, _ := st.DDNSProfile(fake4ProfileID(t, st))
	stored.LastError = "cloudflare: api error (status 403)"
	if err := st.UpsertDDNSProfile(stored); err != nil {
		t.Fatal(err)
	}
	tick()
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("failed profile was not retried: wrote %d, want 1", n)
	}
	if got, _ := st.DDNSProfile(stored.ID); got.LastError != "" {
		t.Fatalf("retry did not clear the error: %q", got.LastError)
	}
}

func fake4ProfileID(t *testing.T, st *store.Store) string {
	t.Helper()
	all := st.DDNSProfiles()
	if len(all) != 1 {
		t.Fatalf("want exactly one profile, got %d", len(all))
	}
	return all[0].ID
}

// TestDDNSFailedRunKeepsPreviousIP pins that a failed publish is not recorded
// as one. The column reads as "what is in DNS now" and the sweep compares
// against it, so an attempted-but-unwritten value both misleads the operator
// and lets the retry be skipped.
func TestDDNSFailedRunKeepsPreviousIP(t *testing.T) {
	srv, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertNode(model.Node{ID: "n1", PublicIP: "203.0.113.20"}); err != nil {
		t.Fatal(err)
	}
	fake := &failingProvider{}
	srv.ddnsProvider = func(model.DDNSProfile) (ddns.Provider, error) { return fake, nil }
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }

	create := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"x","node_id":"n1","provider":"webhook","webhook_url":"https://example.com/h","domains":["a.example.com"],"enable_ipv4":true}`, cookies, csrf)
	defer create.Body.Close()
	var made struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&made)

	// Seed a previously published address.
	seed, _ := st.DDNSProfile(made.ID)
	seed.LastIPv4 = "203.0.113.1"
	if err := st.UpsertDDNSProfile(seed); err != nil {
		t.Fatal(err)
	}

	if n := srv.sweepDDNSOnce(); n != 0 {
		t.Fatalf("a failed publish counted as written: %d", n)
	}
	got, _ := st.DDNSProfile(made.ID)
	if got.LastIPv4 != "203.0.113.1" {
		t.Fatalf("failed publish overwrote the last known address: %q", got.LastIPv4)
	}
	if got.LastError == "" {
		t.Fatal("failed publish recorded no error")
	}

	// Once the provider recovers and the interval has passed, the sweep
	// retries and records for real.
	fake.ok = true
	clock = clock.Add(10 * time.Minute)
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("recovered profile was not retried: %d", n)
	}
	if got, _ := st.DDNSProfile(made.ID); got.LastIPv4 != "203.0.113.20" || got.LastError != "" {
		t.Fatalf("recovery not recorded: ip=%q err=%q", got.LastIPv4, got.LastError)
	}
}

type failingProvider struct{ ok bool }

func (f *failingProvider) Kind() string { return "failing" }
func (f *failingProvider) SetRecord(context.Context, ddns.Record) error {
	if f.ok {
		return nil
	}
	return errors.New("provider refused")
}

// TestDDNSIntervalSpacesRetries covers the per-profile interval.
//
// The interval matters most for a profile the provider keeps rejecting: it is
// attempted on every sweep, so without a per-profile cadence a datacenter
// machine that will not change its address for a year still retried a failing
// write every five minutes.
func TestDDNSIntervalSpacesRetries(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	base := model.DDNSProfile{}

	if !ddnsDue(base, now) {
		t.Fatal("a profile that never ran must be due")
	}

	base.LastRunAt = now.Add(-2 * time.Minute)
	if ddnsDue(base, now) {
		t.Fatal("default interval is five minutes, two is not due yet")
	}
	base.LastRunAt = now.Add(-6 * time.Minute)
	if !ddnsDue(base, now) {
		t.Fatal("past the default interval and still not due")
	}

	// Twelve hours for a datacenter profile.
	slow := model.DDNSProfile{IntervalSeconds: 12 * 3600, LastRunAt: now.Add(-6 * time.Hour)}
	if ddnsDue(slow, now) {
		t.Fatal("six hours into a twelve hour interval must not be due")
	}
	slow.LastRunAt = now.Add(-13 * time.Hour)
	if !ddnsDue(slow, now) {
		t.Fatal("past a twelve hour interval and still not due")
	}

	// Minutes for a residential one.
	fast := model.DDNSProfile{IntervalSeconds: 300, LastRunAt: now.Add(-6 * time.Minute)}
	if !ddnsDue(fast, now) {
		t.Fatal("past a five minute interval and still not due")
	}

	// A negative or zero value falls back rather than running every tick.
	odd := model.DDNSProfile{IntervalSeconds: -1, LastRunAt: now.Add(-1 * time.Minute)}
	if ddnsDue(odd, now) {
		t.Fatal("a nonsense interval must fall back to the default, not to always-due")
	}
}

// TestDDNSSweepHonoursInterval checks the gate is actually wired into the sweep.
func TestDDNSSweepHonoursInterval(t *testing.T) {
	srv, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertNode(model.Node{ID: "n1", PublicIP: "203.0.113.30"}); err != nil {
		t.Fatal(err)
	}
	fake := &fakeProvider{}
	srv.ddnsProvider = func(model.DDNSProfile) (ddns.Provider, error) { return fake, nil }

	create := doJSON(t, handler, http.MethodPost, "/api/ddns",
		`{"name":"slow","node_id":"n1","provider":"webhook","webhook_url":"https://example.com/h","domains":["a.example.com"],"enable_ipv4":true,"interval_seconds":43200}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create: %d", create.StatusCode)
	}

	// Never run, so the first sweep publishes.
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("first sweep wrote %d, want 1", n)
	}
	// The address moves, but the profile asked for twelve hours.
	if err := st.UpsertNode(model.Node{ID: "n1", PublicIP: "203.0.113.31"}); err != nil {
		t.Fatal(err)
	}
	if n := srv.sweepDDNSOnce(); n != 0 {
		t.Fatalf("sweep ignored the interval: wrote %d", n)
	}
	if len(fake.records) != 1 {
		t.Fatalf("provider hit inside the interval: %+v", fake.records)
	}
}
