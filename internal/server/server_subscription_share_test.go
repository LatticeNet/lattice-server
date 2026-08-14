package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestSharePathFromRequest(t *testing.T) {
	validToken := strings.Repeat("a", 32)
	cases := []struct {
		name      string
		path      string
		wantSlug  string
		wantToken string
		wantOK    bool
	}{
		{"two segments", "/sub/team-alpha/" + validToken, "team-alpha", validToken, true},
		{"single segment is gone", "/sub/" + validToken, "", "", false},
		{"three segments", "/sub/a/b/c", "", "", false},
		{"empty slug", "/sub//" + validToken, "", "", false},
		{"empty token", "/sub/team/", "", "", false},
		{"slug rejects uppercase", "/sub/Team/" + validToken, "", "", false},
		{"slug rejects leading hyphen", "/sub/-team/" + validToken, "", "", false},
		{"slug rejects underscore", "/sub/team_a/" + validToken, "", "", false},
		{"token too short", "/sub/team/short", "", "", false},
		{"traversal", "/sub/../" + validToken, "", "", false},
		{"not a sub path", "/api/team/" + validToken, "", "", false},
		{"bare prefix", "/sub/", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slug, token, ok := sharePathFromRequest(tc.path)
			if ok != tc.wantOK || slug != tc.wantSlug || token != tc.wantToken {
				t.Fatalf("got (%q,%q,%v) want (%q,%q,%v)", slug, token, ok, tc.wantSlug, tc.wantToken, tc.wantOK)
			}
		})
	}
}

// The slug charset must stay narrow enough that a slug can never be mistaken for
// a token, and never carry path syntax.
func TestShareSlugRejectsPathSyntax(t *testing.T) {
	for _, bad := range []string{"a/b", "a\\b", "..", ".", "a b", "a%2fb", ""} {
		if shareSlugRe.MatchString(bad) {
			t.Fatalf("slug %q was accepted", bad)
		}
	}
	for _, good := range []string{"a", "team", "team-alpha", "share-for-someone", "a1-2-3"} {
		if !shareSlugRe.MatchString(good) {
			t.Fatalf("slug %q was rejected", good)
		}
	}
}

func newShareTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func mustUpsertShare(t *testing.T, st *store.Store, share model.SubscriptionShare) {
	t.Helper()
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatalf("upsert share %s: %v", share.ID, err)
	}
}

// Every rejection reason must be the same nothing. A caller able to tell them
// apart would learn which of its guesses was a real token.
func TestResolveShareRejectionsAreIndistinguishable(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Now().UTC()
	past := now.Add(-time.Hour)

	mustUpsertShare(t, st, model.SubscriptionShare{ID: "a", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "b", Slug: "off", Token: strings.Repeat("b", 32), Enabled: false})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "c", Slug: "old", Token: strings.Repeat("c", 32), Enabled: true, ExpiresAt: &past})

	if _, ok := s.resolveShare("team", strings.Repeat("a", 32), now); !ok {
		t.Fatal("valid share did not resolve")
	}
	for _, tc := range []struct{ name, slug, token string }{
		{"unknown token", "team", strings.Repeat("z", 32)},
		{"right token wrong slug", "wrong", strings.Repeat("a", 32)},
		{"disabled share", "off", strings.Repeat("b", 32)},
		{"expired share", "old", strings.Repeat("c", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := s.resolveShare(tc.slug, tc.token, now); ok {
				t.Fatalf("%s resolved; every rejection must look the same", tc.name)
			}
		})
	}
}

// A share whose expiry is in the future still resolves; the boundary is
// exclusive at the instant of expiry.
func TestResolveShareExpiryBoundary(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Now().UTC()
	at := now
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "a", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true, ExpiresAt: &at})
	if _, ok := s.resolveShare("team", strings.Repeat("a", 32), now); ok {
		t.Fatal("a share expiring exactly now still resolved")
	}
	future := now.Add(time.Minute)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "b", Slug: "live", Token: strings.Repeat("b", 32), Enabled: true, ExpiresAt: &future})
	if _, ok := s.resolveShare("live", strings.Repeat("b", 32), now); !ok {
		t.Fatal("a share expiring in the future did not resolve")
	}
}

func shareRequest(path, ua string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return req
}

// This is the single most destructive way the endpoint can fail: a proxy client
// that receives an empty but successful subscription deletes every node it had.
// A core proxy-user source with no eligible inbound renders zero endpoints, which
// is exactly that situation arriving through a legitimate path.
func TestSubscriptionShareNeverServesEmptyBodyWith200(t *testing.T) {
	s, st := newShareTestServer(t)
	if err := st.UpsertProxyUser(model.ProxyUser{ID: "u1", Name: "u1", UUID: "uuid", SubToken: "unused"}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "s1", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "u1"},
	})

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+strings.Repeat("a", 32), "Surge/2000"))

	if rec.Code == http.StatusOK {
		t.Fatalf("empty render returned 200 with body %q; a client would wipe its nodes", rec.Body.String())
	}
	// And not a 5xx: an internal-error status would confirm the token was valid
	// and only the content empty. See TestEverySubscriptionRejectionIsByteIdentical.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the same 404 every other rejection returns", rec.Code)
	}
}

func TestSubscriptionShareUnknownTokenIs404(t *testing.T) {
	s, st := newShareTestServer(t)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true})

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+strings.Repeat("z", 32), "Surge/2000"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// A valid token behind the wrong slug must be byte-identical to an unknown
// token, response body included.
func TestSubscriptionShareWrongSlugMatchesUnknownTokenExactly(t *testing.T) {
	s, st := newShareTestServer(t)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true})

	wrongSlug := httptest.NewRecorder()
	s.handleSubscriptionShare(wrongSlug, shareRequest("/sub/other/"+strings.Repeat("a", 32), "Surge/2000"))

	unknown := httptest.NewRecorder()
	s.handleSubscriptionShare(unknown, shareRequest("/sub/other/"+strings.Repeat("z", 32), "Surge/2000"))

	if wrongSlug.Code != unknown.Code {
		t.Fatalf("status differs: wrong slug %d, unknown token %d", wrongSlug.Code, unknown.Code)
	}
	// request_id is deliberately unique per request and says nothing about the
	// token, so it is normalized away; everything else must match exactly.
	if got, want := stripRequestID(wrongSlug.Body.String()), stripRequestID(unknown.Body.String()); got != want {
		t.Fatalf("body differs:\nwrong slug: %q\nunknown:    %q", got, want)
	}
}

func TestSubscriptionShareRejectsNonGET(t *testing.T) {
	s, st := newShareTestServer(t)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sub/team/"+strings.Repeat("a", 32), nil)
	s.handleSubscriptionShare(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — a 405 would confirm the path exists", rec.Code)
	}
}

// No audit event for this endpoint may ever contain the raw token.
func TestSubscriptionShareAuditNeverCarriesTheRawToken(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true})

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "Surge/2000"))

	events := st.AuditEvents()
	if len(events) == 0 {
		t.Fatal("no audit event recorded")
	}
	for _, ev := range events {
		for k, v := range ev.Metadata {
			if strings.Contains(v, token) {
				t.Fatalf("audit metadata %q carried the raw token: %q", k, v)
			}
		}
		if strings.Contains(ev.Reason, token) {
			t.Fatalf("audit reason carried the raw token: %q", ev.Reason)
		}
	}
}

func TestSubscriptionShareStaleCacheHitSetsHeaderAndSafeAudit(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}})
	fetchedAt := s.now().Add(-time.Hour)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "last-good", FetchedAt: fetchedAt,
		LastAttemptAt: fetchedAt, FetchError: "temporary outage", Stale: true}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{}, errors.New("still unavailable")
	}
	key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	version := subscriptionContentHash("last-good")
	s.subscriptionCache.PutSnapshot(key, []byte("last-good"), "text/plain", "upload=1", version, "", true, fetchedAt, s.now())
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token+"?format=plain", "Surge/2000"))
	if rec.Code != http.StatusOK || rec.Body.String() != "last-good" || rec.Header().Get("X-Lattice-Subscription-Stale") != "true" {
		t.Fatalf("stale cache response = code %d header %q body %q", rec.Code, rec.Header().Get("X-Lattice-Subscription-Stale"), rec.Body.String())
	}
	for _, event := range st.AuditEvents() {
		if event.Action == auditActionShareFetch && event.Decision == "allow" {
			if event.Metadata["stale"] != "true" || event.Metadata["snapshot_age_seconds"] == "" {
				t.Fatalf("share stale audit = %+v", event.Metadata)
			}
			if _, exposed := event.Metadata["source_version"]; exposed {
				t.Fatalf("legacy audit exposed a public source_version field: %+v", event.Metadata)
			}
			if strings.Contains(fmt.Sprint(event.Metadata), version) {
				t.Fatalf("legacy raw-derived revalidation hash leaked into audit: %+v", event.Metadata)
			}
			if strings.Contains(strings.ToLower(fmt.Sprint(event.Metadata)), "error") {
				t.Fatalf("diagnostic leaked into share audit: %+v", event.Metadata)
			}
		}
	}
}

func TestSubscriptionShareStaleCacheHitRevalidatesAndClearsHeaderOnRecovery(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}})
	fetchedAt := s.now().Add(-time.Minute)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "last-good", FetchedAt: fetchedAt,
		LastAttemptAt: fetchedAt, FetchError: "temporary outage", Stale: true}); err != nil {
		t.Fatal(err)
	}
	key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	s.subscriptionCache.PutSnapshot(key, []byte("rendered-last-good"), "text/plain", "upload=1", subscriptionContentHash("last-good"), "", true, fetchedAt, s.now())
	calls := 0
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		calls++
		return model.SubscriptionSnapshot{Raw: "last-good", Userinfo: "upload=2"}, nil
	}

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token+"?format=plain", "Surge/2000"))
	if rec.Code != http.StatusOK || rec.Body.String() != "rendered-last-good" || rec.Header().Get("X-Lattice-Subscription-Stale") != "" || rec.Header().Get("Subscription-Userinfo") != "upload=2" || calls != 1 {
		t.Fatalf("recovered cache response = code %d stale %q userinfo %q body %q calls %d", rec.Code, rec.Header().Get("X-Lattice-Subscription-Stale"), rec.Header().Get("Subscription-Userinfo"), rec.Body.String(), calls)
	}
	stored, ok := st.SubscriptionSnapshot("p", "graph")
	if !ok || stored.Stale || stored.FetchError != "" {
		t.Fatalf("recovered snapshot = %+v ok=%v", stored, ok)
	}
	if cached, ok := s.subscriptionCache.GetStale(key); ok {
		t.Fatalf("recovery did not invalidate source cache: %+v", cached)
	}
}

func TestSubscriptionShareExpiredCacheRevalidationRefreshesUserinfo(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}})
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "same", Userinfo: "upload=2", FetchedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	s.subscriptionCache.PutSnapshot(key, []byte("same-render"), "text/plain", "upload=1", subscriptionContentHash("same"), "", false, s.now(), s.now().Add(-subscriptionCacheTTL-time.Second))

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token+"?format=plain", "Surge/2000"))
	if rec.Code != http.StatusOK || rec.Body.String() != "same-render" || rec.Header().Get("Subscription-Userinfo") != "upload=2" {
		t.Fatalf("revalidated response = code %d userinfo %q body %q", rec.Code, rec.Header().Get("Subscription-Userinfo"), rec.Body.String())
	}
	cached, ok := s.subscriptionCache.GetSnapshot(key, s.now())
	if !ok || cached.userinfo != "upload=2" {
		t.Fatalf("revalidated cache metadata = %+v ok=%v", cached, ok)
	}
}

func TestSubscriptionSharePropagatesStaleAndRecoveryAcrossSiblingShares(t *testing.T) {
	s, st := newShareTestServer(t)
	tokenA, tokenB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for _, share := range []model.SubscriptionShare{
		{ID: "s1", Slug: "one", Token: tokenA, Enabled: true, DefaultFormat: "plain", Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}},
		{ID: "s2", Slug: "two", Token: tokenB, Enabled: true, DefaultFormat: "base64", Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}},
	} {
		mustUpsertShare(t, st, share)
	}
	fetchedAt := s.now().Add(-time.Hour)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "last-good", Userinfo: "upload=1", FetchedAt: fetchedAt}); err != nil {
		t.Fatal(err)
	}
	keyA := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	keyB := subscriptionCacheKey{ShareID: "s2", Format: "base64", UAClass: "clash"}
	version := subscriptionContentHash("last-good")
	s.subscriptionCache.PutSnapshot(keyA, []byte("body-a"), "text/plain", "upload=1", version, "", false, fetchedAt, s.now().Add(-subscriptionCacheTTL-time.Second))
	s.subscriptionCache.PutSnapshot(keyB, []byte("body-b"), "text/plain", "upload=1", version, "", false, fetchedAt, s.now())
	fetchCalls := 0
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetchCalls++
		return model.SubscriptionSnapshot{}, errors.New("provider down")
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		return renderedSubscription{Body: []byte("rendered-" + share.ID), ContentType: "text/plain", Userinfo: snap.Userinfo,
			Stale: snap.Stale, RevalidationVersion: subscriptionRevalidationVersion(snap), SourceVersion: snap.SourceVersion, FetchedAt: snap.FetchedAt}, nil
	}

	first := httptest.NewRecorder()
	s.handleSubscriptionShare(first, shareRequest("/sub/one/"+tokenA+"?format=plain", "Surge/2000"))
	second := httptest.NewRecorder()
	s.handleSubscriptionShare(second, shareRequest("/sub/two/"+tokenB+"?format=base64", "Clash/1.0"))
	for name, rec := range map[string]*httptest.ResponseRecorder{"first": first, "second": second} {
		if rec.Code != http.StatusOK || rec.Header().Get("X-Lattice-Subscription-Stale") != "true" {
			t.Fatalf("%s sibling stale response = code %d header %q body %q", name, rec.Code, rec.Header().Get("X-Lattice-Subscription-Stale"), rec.Body.String())
		}
	}
	for _, event := range st.AuditEvents() {
		if event.Action == auditActionShareFetch && event.Decision == "allow" && event.Metadata["stale"] != "true" {
			t.Fatalf("sibling stale audit was fresh: %+v", event.Metadata)
		}
	}

	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetchCalls++
		return model.SubscriptionSnapshot{Raw: "last-good", Userinfo: "upload=2"}, nil
	}
	recoveredA := httptest.NewRecorder()
	s.handleSubscriptionShare(recoveredA, shareRequest("/sub/one/"+tokenA+"?format=plain", "Surge/2000"))
	recoveredB := httptest.NewRecorder()
	s.handleSubscriptionShare(recoveredB, shareRequest("/sub/two/"+tokenB+"?format=base64", "Clash/1.0"))
	for name, rec := range map[string]*httptest.ResponseRecorder{"first": recoveredA, "second": recoveredB} {
		if rec.Code != http.StatusOK || rec.Header().Get("X-Lattice-Subscription-Stale") != "" || rec.Header().Get("Subscription-Userinfo") != "upload=2" {
			t.Fatalf("%s sibling recovery = code %d stale %q userinfo %q", name, rec.Code, rec.Header().Get("X-Lattice-Subscription-Stale"), rec.Header().Get("Subscription-Userinfo"))
		}
	}
	if fetchCalls != 3 {
		t.Fatalf("provider fetch calls=%d, want two outage attempts and one recovery", fetchCalls)
	}
}

var requestIDInBody = regexp.MustCompile(`"request_id":"[^"]*"`)

func stripRequestID(body string) string {
	return requestIDInBody.ReplaceAllString(body, `"request_id":"<normalized>"`)
}
