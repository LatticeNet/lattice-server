package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/secret"
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
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
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
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}})
	fetchedAt := now.Add(-time.Hour)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "last-good", FetchedAt: fetchedAt,
		LastAttemptAt: now, FetchError: "provider_fetch_failed", Stale: true}); err != nil {
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
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}})
	fetchedAt := now.Add(-time.Minute)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "last-good", FetchedAt: fetchedAt,
		LastAttemptAt: now.Add(-subscriptionStaleRetryInterval - time.Second), FetchError: "provider_fetch_failed", Stale: true}); err != nil {
		t.Fatal(err)
	}
	key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	s.subscriptionCache.PutSnapshot(key, []byte("rendered-last-good"), "text/plain", "upload=1", subscriptionContentHash("last-good"), "", true, fetchedAt, s.now())
	calls := 0
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		calls++
		return model.SubscriptionSnapshot{Raw: "last-good", Userinfo: "upload=2"}, nil
	}
	s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, ok := s.subscriptionSnapshotEpoch("p", "graph", snap)
		if !ok {
			return renderedSubscription{}, errors.New("snapshot changed")
		}
		return renderedSubscription{Body: []byte("rendered-last-good"), ContentType: "text/plain", Userinfo: snap.Userinfo,
			RevalidationVersion: subscriptionRevalidationVersion(snap), SourceVersion: snap.SourceVersion, SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
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
	if cached, ok := s.subscriptionCache.GetStale(key); !ok || cached.stale || cached.userinfo != "upload=2" || string(cached.body) != "rendered-last-good" {
		t.Fatalf("recovery cache was not rebuilt truthfully: %+v ok=%v", cached, ok)
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
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	tokenA, tokenB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for _, share := range []model.SubscriptionShare{
		{ID: "s1", Slug: "one", Token: tokenA, Enabled: true, DefaultFormat: "plain", Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}},
		{ID: "s2", Slug: "two", Token: tokenB, Enabled: true, DefaultFormat: "base64", Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}},
	} {
		mustUpsertShare(t, st, share)
	}
	fetchedAt := now.Add(-time.Hour)
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
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
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
	now = now.Add(subscriptionStaleRetryInterval + time.Second)
	recoveredA := httptest.NewRecorder()
	s.handleSubscriptionShare(recoveredA, shareRequest("/sub/one/"+tokenA+"?format=plain", "Surge/2000"))
	recoveredB := httptest.NewRecorder()
	s.handleSubscriptionShare(recoveredB, shareRequest("/sub/two/"+tokenB+"?format=base64", "Clash/1.0"))
	for name, rec := range map[string]*httptest.ResponseRecorder{"first": recoveredA, "second": recoveredB} {
		if rec.Code != http.StatusOK || rec.Header().Get("X-Lattice-Subscription-Stale") != "" || rec.Header().Get("Subscription-Userinfo") != "upload=2" {
			t.Fatalf("%s sibling recovery = code %d stale %q userinfo %q", name, rec.Code, rec.Header().Get("X-Lattice-Subscription-Stale"), rec.Header().Get("Subscription-Userinfo"))
		}
	}
	if fetchCalls != 2 {
		t.Fatalf("provider fetch calls=%d, want one bounded outage attempt and one recovery", fetchCalls)
	}
}

func TestSubscriptionShareRevisionMismatchRendersInsteadOfStampingReplacement(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	share := model.SubscriptionShare{ID: "s1", Slug: "one", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
	mustUpsertShare(t, st, share)
	now := s.now()
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "same", Userinfo: "current-ui", FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	version := subscriptionContentHash("same")
	s.subscriptionCache.PutSnapshot(key, []byte("old-body"), "text/plain", "old-ui", version, "", false, now, now.Add(-subscriptionCacheTTL-time.Second))
	s.subscriptionBeforeCacheExtend = func() {
		s.subscriptionCache.PutSnapshot(key, []byte("replacement"), "text/plain", "replacement-ui", "new-version", "", false, now, now)
		s.subscriptionBeforeCacheExtend = nil
	}
	s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		return renderedSubscription{Body: []byte("rerendered"), ContentType: "text/plain", Userinfo: snap.Userinfo,
			RevalidationVersion: subscriptionRevalidationVersion(snap), FetchedAt: snap.FetchedAt}, nil
	}
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/one/"+token+"?format=plain", "Surge/2000"))
	if rec.Code != http.StatusOK || rec.Body.String() != "rerendered" || rec.Header().Get("Subscription-Userinfo") != "current-ui" {
		t.Fatalf("revision mismatch response = code %d body %q userinfo %q", rec.Code, rec.Body.String(), rec.Header().Get("Subscription-Userinfo"))
	}
	if stale, ok := s.subscriptionCache.GetStale(key); ok && string(stale.body) == "old-body" {
		t.Fatalf("old lookup body survived revision mismatch: %+v", stale)
	}
}

func TestSubscriptionShareRejectsLateRenderCachePutAfterSourceTransition(t *testing.T) {
	for _, transition := range []string{"stale", "version"} {
		t.Run(transition, func(t *testing.T) {
			s, st := newShareTestServer(t)
			token := strings.Repeat("a", 32)
			share := model.SubscriptionShare{ID: "s1", Slug: "one", Token: token, Enabled: true, DefaultFormat: "plain",
				Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
			mustUpsertShare(t, st, share)
			old := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "old", FetchedAt: s.now()}
			if err := st.UpsertSubscriptionSnapshot(old); err != nil {
				t.Fatal(err)
			}
			started, release := make(chan struct{}), make(chan struct{})
			var first sync.Once
			renderCalls := 0
			s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
				renderCalls++
				blocked := false
				first.Do(func() {
					blocked = true
					close(started)
				})
				if blocked {
					<-release
					return renderedSubscription{Body: []byte("old-render"), ContentType: "text/plain", RevalidationVersion: subscriptionRevalidationVersion(snap), FetchedAt: snap.FetchedAt}, nil
				}
				body := "new-render"
				if snap.Stale {
					body = "stale-current"
				}
				return renderedSubscription{Body: []byte(body), ContentType: "text/plain", Userinfo: snap.Userinfo,
					Stale: snap.Stale, RevalidationVersion: subscriptionRevalidationVersion(snap), SourceVersion: snap.SourceVersion, FetchedAt: snap.FetchedAt}, nil
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				rec := httptest.NewRecorder()
				s.handleSubscriptionShare(rec, shareRequest("/sub/one/"+token+"?format=plain", "Surge/2000"))
				done <- rec
			}()
			<-started
			if transition == "stale" {
				s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
					return model.SubscriptionSnapshot{}, errors.New("down")
				}
			} else {
				s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
					return model.SubscriptionSnapshot{Raw: "new"}, nil
				}
			}
			if _, err := s.snapshotFor(context.Background(), "p", "graph", true); err != nil {
				t.Fatal(err)
			}
			close(release)
			rec := <-done
			wantBody := "new-render"
			if transition == "stale" {
				wantBody = "stale-current"
			}
			if rec.Code != http.StatusOK || rec.Body.String() != wantBody || renderCalls != 2 {
				t.Fatalf("late render response code=%d body=%q calls=%d want body=%q calls=2", rec.Code, rec.Body.String(), renderCalls, wantBody)
			}
			key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
			if cached, ok := s.subscriptionCache.GetStale(key); ok && string(cached.body) == "old-render" {
				t.Fatalf("late render reintroduced old cache after %s: %+v", transition, cached)
			}
		})
	}
}

func TestSubscriptionShareFailsClosedWhenSourceChangesDuringBothRenderAttempts(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	share := model.SubscriptionShare{ID: "s1", Slug: "one", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
	mustUpsertShare(t, st, share)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "base", FetchedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		calls++
		publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "graph"})
		publication.mu.Lock()
		publication.epoch++
		publication.mu.Unlock()
		return renderedSubscription{Body: []byte("superseded"), ContentType: "text/plain", RevalidationVersion: subscriptionRevalidationVersion(snap), FetchedAt: snap.FetchedAt}, nil
	}
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/one/"+token+"?format=plain", "Surge/2000"))
	if rec.Code != http.StatusNotFound || calls != 2 || strings.Contains(rec.Body.String(), "superseded") {
		t.Fatalf("continuous transition response code=%d calls=%d body=%q", rec.Code, calls, rec.Body.String())
	}
	if _, ok := s.subscriptionCache.GetStale(subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}); ok {
		t.Fatal("superseded render entered cache")
	}
}

func TestSubscriptionShareCacheHitCannotObservePartialSourcePublication(t *testing.T) {
	for _, transition := range []string{"stale", "version"} {
		t.Run(transition, func(t *testing.T) {
			s, st := newShareTestServer(t)
			token := strings.Repeat("a", 32)
			share := model.SubscriptionShare{ID: "s1", Slug: "one", Token: token, Enabled: true, DefaultFormat: "plain",
				Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
			mustUpsertShare(t, st, share)
			old := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "old", FetchedAt: s.now()}
			if err := st.UpsertSubscriptionSnapshot(old); err != nil {
				t.Fatal(err)
			}
			key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
			s.subscriptionCache.PutSnapshot(key, []byte("old-cache-hit"), "text/plain", "", subscriptionRevalidationVersion(old), "", false, old.FetchedAt, s.now())

			persisted, releasePublish := make(chan struct{}), make(chan struct{})
			var persistOnce sync.Once
			s.subscriptionSnapshotPersist = func(snapshot model.SubscriptionSnapshot) (bool, error) {
				committed, err := st.UpsertSubscriptionSnapshotWithCommit(snapshot)
				if err != nil {
					return committed, err
				}
				persistOnce.Do(func() { close(persisted) })
				<-releasePublish
				return true, nil
			}
			if transition == "stale" {
				s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
					return model.SubscriptionSnapshot{}, errors.New("down")
				}
			} else {
				s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
					return model.SubscriptionSnapshot{Raw: "new"}, nil
				}
			}
			s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
				body := "new-render"
				if snap.Stale {
					body = "stale-current"
				}
				return renderedSubscription{Body: []byte(body), ContentType: "text/plain", Stale: snap.Stale,
					RevalidationVersion: subscriptionRevalidationVersion(snap), SourceVersion: snap.SourceVersion, FetchedAt: snap.FetchedAt}, nil
			}
			lookupStarted := make(chan struct{}, 1)
			s.subscriptionCacheLookupWaiter = lookupStarted
			refreshDone := make(chan error, 1)
			go func() {
				_, err := s.snapshotFor(context.Background(), "p", "graph", true)
				refreshDone <- err
			}()
			<-persisted
			responseDone := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				rec := httptest.NewRecorder()
				s.handleSubscriptionShare(rec, shareRequest("/sub/one/"+token+"?format=plain", "Surge/2000"))
				responseDone <- rec
			}()
			<-lookupStarted
			publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "graph"})
			if publication.mu.TryLock() {
				publication.mu.Unlock()
				t.Fatal("cache lookup did not contend with the source publication lock")
			}
			close(releasePublish)
			if err := <-refreshDone; err != nil {
				t.Fatal(err)
			}
			rec := <-responseDone
			want := "new-render"
			if transition == "stale" {
				want = "stale-current"
			}
			if rec.Code != http.StatusOK || rec.Body.String() != want || strings.Contains(rec.Body.String(), "old-cache-hit") {
				t.Fatalf("published response code=%d body=%q want=%q", rec.Code, rec.Body.String(), want)
			}
		})
	}
}

func TestSubscriptionShareRefreshPersistenceErrorsAreTerminal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fetchErr  bool
		committed bool
		wantRaw   string
		wantStale bool
	}{
		{name: "committed success durability error", committed: true, wantRaw: "new"},
		{name: "committed stale durability error", fetchErr: true, committed: true, wantRaw: "old", wantStale: true},
		{name: "uncommitted persistence error", wantRaw: "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, st := newShareTestServer(t)
			token := strings.Repeat("a", 32)
			share := model.SubscriptionShare{ID: "share", Slug: "share", Token: token, Enabled: true, DefaultFormat: "plain",
				Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
			mustUpsertShare(t, st, share)
			base := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "old", FetchedAt: s.now().Add(-time.Hour)}
			if err := st.UpsertSubscriptionSnapshot(base); err != nil {
				t.Fatal(err)
			}
			key := subscriptionCacheKey{ShareID: "share", Format: "plain", UAClass: "surge"}
			s.subscriptionCache.PutSnapshot(key, []byte("authoritative-body-must-not-escape"), "text/plain", "", subscriptionRevalidationVersion(base), "", false, base.FetchedAt, s.now().Add(-subscriptionCacheTTL-time.Second))
			s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
				if tc.fetchErr {
					return model.SubscriptionSnapshot{}, errors.New("provider secret must not escape")
				}
				return model.SubscriptionSnapshot{Raw: "new"}, nil
			}
			s.subscriptionSnapshotPersist = func(snapshot model.SubscriptionSnapshot) (bool, error) {
				if tc.committed {
					if err := st.UpsertSubscriptionSnapshot(snapshot); err != nil {
						return false, err
					}
				}
				return tc.committed, errors.New("durability secret must not escape")
			}
			rec := httptest.NewRecorder()
			s.handleSubscriptionShare(rec, shareRequest("/sub/share/"+token+"?format=plain", "Surge/2000"))
			if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "authoritative-body-must-not-escape") || strings.Contains(rec.Body.String(), "secret") {
				t.Fatalf("refresh error escaped as success code=%d body=%q", rec.Code, rec.Body.String())
			}
			if _, ok := s.subscriptionCache.GetStale(key); ok {
				t.Fatal("refresh error left a response cache entry")
			}
			stored, ok := st.SubscriptionSnapshot("p", "graph")
			if !ok || stored.Raw != tc.wantRaw || stored.Stale != tc.wantStale {
				t.Fatalf("durable authority=%+v ok=%v", stored, ok)
			}
			for _, event := range st.AuditEvents() {
				if strings.Contains(event.Reason+fmt.Sprint(event.Metadata), "secret") {
					t.Fatalf("refresh diagnostic reached audit: %+v", event)
				}
			}
		})
	}
}

func TestSubscriptionShareRevalidationCannotExtendAcrossPartialSourcePublication(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	share := model.SubscriptionShare{ID: "s1", Slug: "one", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
	mustUpsertShare(t, st, share)
	now := s.now()
	old := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "old", FetchedAt: now}
	if err := st.UpsertSubscriptionSnapshot(old); err != nil {
		t.Fatal(err)
	}
	key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	s.subscriptionCache.PutSnapshot(key, []byte("old-cache"), "text/plain", "", subscriptionRevalidationVersion(old), "", false, now, now.Add(-subscriptionCacheTTL-time.Second))

	persisted, releasePublish := make(chan struct{}), make(chan struct{})
	s.subscriptionSnapshotPersist = func(snapshot model.SubscriptionSnapshot) (bool, error) {
		committed, err := st.UpsertSubscriptionSnapshotWithCommit(snapshot)
		if err != nil {
			return committed, err
		}
		close(persisted)
		<-releasePublish
		return true, nil
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "new"}, nil
	}
	refreshDone := make(chan error, 1)
	var startRefresh sync.Once
	s.subscriptionBeforeCacheExtend = func() {
		startRefresh.Do(func() {
			go func() {
				_, err := s.snapshotFor(context.Background(), "p", "graph", true)
				refreshDone <- err
			}()
			<-persisted
		})
	}
	extendStarted := make(chan struct{}, 1)
	s.subscriptionCacheExtendWaiter = extendStarted
	s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		return renderedSubscription{Body: []byte("render-" + snap.Raw), ContentType: "text/plain",
			RevalidationVersion: subscriptionRevalidationVersion(snap), FetchedAt: snap.FetchedAt}, nil
	}
	responseDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest("/sub/one/"+token+"?format=plain", "Surge/2000"))
		responseDone <- rec
	}()
	<-extendStarted
	publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "graph"})
	if publication.mu.TryLock() {
		publication.mu.Unlock()
		t.Fatal("cache extension did not contend with partial source publication")
	}
	close(releasePublish)
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}
	rec := <-responseDone
	if rec.Code != http.StatusOK || rec.Body.String() != "render-new" || strings.Contains(rec.Body.String(), "old-cache") {
		t.Fatalf("revalidation escaped old response: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestPluginInvalidationRejectsBlockedOldRender(t *testing.T) {
	s, st := newShareTestServer(t)
	token := strings.Repeat("a", 32)
	share := model.SubscriptionShare{ID: "s1", Slug: "one", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}}
	mustUpsertShare(t, st, share)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "same", FetchedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	calls := 0
	s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		calls++
		blocked := false
		first.Do(func() { blocked = true; close(started) })
		if blocked {
			<-release
			return renderedSubscription{Body: []byte("old-render"), ContentType: "text/plain", RevalidationVersion: subscriptionRevalidationVersion(snap), FetchedAt: snap.FetchedAt}, nil
		}
		return renderedSubscription{Body: []byte("new-render"), ContentType: "text/plain", RevalidationVersion: subscriptionRevalidationVersion(snap), FetchedAt: snap.FetchedAt}, nil
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest("/sub/one/"+token+"?format=plain", "Surge/2000"))
		done <- rec
	}()
	<-started
	s.invalidateSharesForPlugin("p")
	close(release)
	rec := <-done
	if rec.Code != http.StatusOK || rec.Body.String() != "new-render" || calls != 2 {
		t.Fatalf("plugin invalidation response code=%d body=%q calls=%d", rec.Code, rec.Body.String(), calls)
	}
	key := subscriptionCacheKey{ShareID: "s1", Format: "plain", UAClass: "surge"}
	if cached, ok := s.subscriptionCache.GetStale(key); !ok || string(cached.body) != "new-render" {
		t.Fatalf("plugin invalidation cache=%+v ok=%v", cached, ok)
	}
}

func TestSubscriptionFailureDiagnosticsAreSanitizedAtRestAndInAudit(t *testing.T) {
	s, st := newShareTestServer(t)
	canary := "vless://11111111-1111-4111-8111-111111111111:secret@example.com/private-key"
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: "last-good", FetchedAt: s.now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{}, errors.New(canary)
	}
	if _, err := s.snapshotFor(context.Background(), "p", "s", true); err != nil {
		t.Fatal(err)
	}
	stored, _ := st.SubscriptionSnapshot("p", "s")
	if stored.FetchError != "provider_fetch_failed" || strings.Contains(stored.FetchError, canary) {
		t.Fatalf("hostile diagnostic persisted: %+v", stored)
	}
	for _, event := range st.AuditEvents() {
		if strings.Contains(event.Reason+fmt.Sprint(event.Metadata), canary) {
			t.Fatalf("hostile diagnostic reached audit: %+v", event)
		}
	}
	share := model.SubscriptionShare{ID: "s1", Slug: "one", Token: strings.Repeat("a", 32), Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "s"}}
	mustUpsertShare(t, st, share)
	s.subscriptionFetch = nil
	s.subscriptionRender = func(context.Context, model.SubscriptionShare, string, string, shareRenderVariant, model.SubscriptionSnapshot) (renderedSubscription, error) {
		return renderedSubscription{}, errors.New(canary)
	}
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/one/"+share.Token+"?format=plain", "Surge/2000"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("hostile render status=%d", rec.Code)
	}
	for _, event := range st.AuditEvents() {
		if strings.Contains(event.Reason+fmt.Sprint(event.Metadata), canary) {
			t.Fatalf("hostile render diagnostic reached audit: %+v", event)
		}
	}
}

func TestSubscriptionFailureDiagnosticsDoNotReachPersistentJSONOrBolt(t *testing.T) {
	canary := "vless://11111111-1111-4111-8111-111111111111:token@example.com/?private-key=TOP-SECRET"
	for _, hot := range []bool{false, true} {
		t.Run(fmt.Sprintf("runtime_hot_%t", hot), func(t *testing.T) {
			dir := t.TempDir()
			statePath := filepath.Join(dir, "state.json")
			boltPath := filepath.Join(dir, "runtime.db")
			cipher, err := secret.NewAESGCM([]byte("0123456789abcdef0123456789abcdef"))
			if err != nil {
				t.Fatal(err)
			}
			st, err := store.OpenWithCipher(statePath, cipher)
			if err != nil {
				t.Fatal(err)
			}
			if hot {
				if err := st.EnableRuntimeBoltHotStore(boltPath); err != nil {
					t.Fatal(err)
				}
			}
			var runtimeLogs bytes.Buffer
			s, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true, Logger: log.New(&runtimeLogs, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s", Raw: "last-good", FetchedAt: s.now().Add(-time.Hour)}); err != nil {
				t.Fatal(err)
			}
			hostile := canary + strings.Repeat("x", 4096)
			s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
				return model.SubscriptionSnapshot{}, errors.New(hostile)
			}
			if _, err := s.snapshotFor(context.Background(), "p", "s", true); err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(hostile))
			if strings.Contains(runtimeLogs.String(), canary) || strings.Contains(runtimeLogs.String(), hex.EncodeToString(digest[:])) {
				t.Fatalf("hostile diagnostic content or digest leaked to runtime log: %q", runtimeLogs.String())
			}
			for _, path := range []string{statePath, boltPath} {
				data, err := os.ReadFile(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), canary) {
					t.Fatalf("hostile diagnostic leaked to %s", filepath.Base(path))
				}
			}
			reopened, err := store.OpenWithCipher(statePath, cipher)
			if err != nil {
				t.Fatal(err)
			}
			if hot {
				if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
					t.Fatal(err)
				}
			}
			stored, ok := reopened.SubscriptionSnapshot("p", "s")
			if !ok || stored.FetchError != "provider_fetch_failed" || strings.Contains(fmt.Sprint(stored), canary) {
				t.Fatalf("reopened hostile diagnostic state = %+v ok=%v", stored, ok)
			}
			for _, event := range reopened.AuditEvents() {
				if strings.Contains(event.Reason+fmt.Sprint(event.Metadata), canary) {
					t.Fatalf("reopened hostile diagnostic audit = %+v", event)
				}
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSubscriptionDiagnosticSummaryIsBoundedAndSecretFree(t *testing.T) {
	canary := "vless://11111111-1111-4111-8111-111111111111:token@example.com/private-key"
	summary := subscriptionDiagnosticSummary(errors.New(canary + strings.Repeat("x", 1<<20)))
	digest := sha256.Sum256([]byte(canary + strings.Repeat("x", 1<<20)))
	if strings.Contains(summary, canary) || strings.Contains(summary, hex.EncodeToString(digest[:])) || len(summary) > 160 {
		t.Fatalf("unsafe diagnostic summary length=%d value=%q", len(summary), summary)
	}
	var logs bytes.Buffer
	s, _ := newShareTestServer(t)
	s.logger = log.New(&logs, "", 0)
	s.logger.Printf("provider failed (%s)", summary)
	if strings.Contains(logs.String(), canary) || strings.Contains(logs.String(), hex.EncodeToString(digest[:])) {
		t.Fatalf("diagnostic content or digest reached logs: %q", logs.String())
	}
}

var requestIDInBody = regexp.MustCompile(`"request_id":"[^"]*"`)

func stripRequestID(body string) string {
	return requestIDInBody.ReplaceAllString(body, `"request_id":"<normalized>"`)
}

// The Sub-Store URL parity contract on the serve path: ?target= names the
// client explicitly and reaches the plugin render, distinct targets cache
// separately, an unknown target is denied like any other bad input, and
// includeUnsupportedProxy rides through as a produce flag.
func TestSubscriptionShareExplicitTargetParameter(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	token := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"}})
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "graph", Raw: "nodes", FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "nodes", FetchedAt: now}, nil
	}
	var variants []shareRenderVariant
	s.subscriptionRender = func(_ context.Context, _ model.SubscriptionShare, _, _ string, variant shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		variants = append(variants, variant)
		epoch, _ := s.subscriptionSnapshotEpoch("p", "graph", snap)
		return renderedSubscription{Body: []byte("for-" + variant.Target), ContentType: "text/plain",
			RevalidationVersion: subscriptionRevalidationVersion(snap), SourceVersion: snap.SourceVersion, SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}

	// Stash and sing-box render and cache independently.
	recA := httptest.NewRecorder()
	s.handleSubscriptionShare(recA, shareRequest("/sub/team/"+token+"?target=Stash&includeUnsupportedProxy=1", "curl/8"))
	recB := httptest.NewRecorder()
	s.handleSubscriptionShare(recB, shareRequest("/sub/team/"+token+"?target=sing-box", "curl/8"))
	if recA.Code != http.StatusOK || recA.Body.String() != "for-Stash" {
		t.Fatalf("target=Stash response = %d %q", recA.Code, recA.Body.String())
	}
	if recB.Code != http.StatusOK || recB.Body.String() != "for-sing-box" {
		t.Fatalf("target=sing-box response = %d %q", recB.Code, recB.Body.String())
	}
	if len(variants) != 2 {
		t.Fatalf("expected two renders (distinct cache keys), got %d", len(variants))
	}
	if variants[0].Target != "Stash" || !variants[0].IncludeUnsupported {
		t.Fatalf("first render variant = %+v", variants[0])
	}
	if variants[1].Target != "sing-box" || variants[1].IncludeUnsupported {
		t.Fatalf("second render variant = %+v", variants[1])
	}

	// A repeat hit with the same target is served from cache: no third render.
	recC := httptest.NewRecorder()
	s.handleSubscriptionShare(recC, shareRequest("/sub/team/"+token+"?target=Stash&includeUnsupportedProxy=1", "curl/8"))
	if recC.Code != http.StatusOK || recC.Body.String() != "for-Stash" || len(variants) != 2 {
		t.Fatalf("cache miss on identical variant: code=%d body=%q renders=%d", recC.Code, recC.Body.String(), len(variants))
	}

	// An unknown target is denied without reaching a render.
	recD := httptest.NewRecorder()
	s.handleSubscriptionShare(recD, shareRequest("/sub/team/"+token+"?target=EvilClient", "curl/8"))
	if recD.Code == http.StatusOK || len(variants) != 2 {
		t.Fatalf("unknown target must be denied before rendering: code=%d renders=%d", recD.Code, len(variants))
	}

	// prettyYaml is its own cache dimension and reaches produce as pretty-yaml.
	recE := httptest.NewRecorder()
	s.handleSubscriptionShare(recE, shareRequest("/sub/team/"+token+"?target=Stash&prettyYaml=1", "curl/8"))
	if recE.Code != http.StatusOK || len(variants) != 3 {
		t.Fatalf("prettyYaml variant should render separately: code=%d renders=%d", recE.Code, len(variants))
	}
	if !variants[2].PrettyYAML || variants[2].options()["pretty-yaml"] != true {
		t.Fatalf("prettyYaml did not reach the produce options: %+v", variants[2])
	}

	// noFlow suppresses the quota header without splitting the cache.
	recF := httptest.NewRecorder()
	s.handleSubscriptionShare(recF, shareRequest("/sub/team/"+token+"?target=Stash&includeUnsupportedProxy=1&noFlow=1", "curl/8"))
	if recF.Code != http.StatusOK || len(variants) != 3 {
		t.Fatalf("noFlow must not add a cache dimension: code=%d renders=%d", recF.Code, len(variants))
	}
	if recF.Header().Get("Subscription-Userinfo") != "" {
		t.Fatalf("noFlow response still carried Subscription-Userinfo: %q", recF.Header().Get("Subscription-Userinfo"))
	}

	// ?platform= is upstream's alias for ?target= and normalizes into the same
	// variant: an aliased repeat of recA's request is a cache hit, not a render.
	recG := httptest.NewRecorder()
	s.handleSubscriptionShare(recG, shareRequest("/sub/team/"+token+"?platform=Stash&includeUnsupportedProxy=1", "curl/8"))
	if recG.Code != http.StatusOK || recG.Body.String() != "for-Stash" || len(variants) != 3 {
		t.Fatalf("platform alias should share target's cache entry: code=%d body=%q renders=%d", recG.Code, recG.Body.String(), len(variants))
	}

	// When both are present, target wins.
	recH := httptest.NewRecorder()
	s.handleSubscriptionShare(recH, shareRequest("/sub/team/"+token+"?target=sing-box&platform=Stash", "curl/8"))
	if recH.Code != http.StatusOK || recH.Body.String() != "for-sing-box" || len(variants) != 3 {
		t.Fatalf("target must win over platform: code=%d body=%q renders=%d", recH.Code, recH.Body.String(), len(variants))
	}
}
