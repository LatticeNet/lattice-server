package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func flightShareServer(t *testing.T) (*Server, *store.Store, string) {
	t.Helper()
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	token := strings.Repeat("f", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "rec"}})
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "rec", Raw: "nodes", FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	return s, st, "/sub/team/" + token
}

func flightRender(s *Server, renders *atomic.Int64, gate <-chan struct{}) func(context.Context, model.SubscriptionShare, string, string, shareRenderVariant, model.SubscriptionSnapshot) (renderedSubscription, error) {
	return func(_ context.Context, share model.SubscriptionShare, format, uaClass string, variant shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		renders.Add(1)
		if gate != nil {
			<-gate
		}
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("rendered " + format + " " + uaClass + " " + variant.Target), ContentType: "text/plain",
			RevalidationVersion: subscriptionRevalidationVersion(snap), SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
}

// Eight cold requests for one key used to run eight plugin renders of
// identical bytes on a pool of two workers. They now run one.
func TestConcurrentMissesForOneKeyRenderOnce(t *testing.T) {
	s, _, path := flightShareServer(t)
	var renders atomic.Int64
	gate := make(chan struct{})
	s.subscriptionRender = flightRender(s, &renders, gate)
	joined := make(chan struct{}, 16)
	s.shareRenderJoinWaiter = joined

	const clients = 8
	var wg sync.WaitGroup
	bodies := make([]string, clients)
	codes := make([]int, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			s.handleSubscriptionShare(rec, shareRequest(path+"?target=ClashMeta", "curl/8"))
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}(i)
	}
	for i := 0; i < clients-1; i++ {
		select {
		case <-joined:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d requests joined the render", i)
		}
	}
	close(gate)
	wg.Wait()
	if got := renders.Load(); got != 1 {
		t.Fatalf("renders = %d, want 1", got)
	}
	for i := range codes {
		if codes[i] != http.StatusOK || bodies[i] != bodies[0] {
			t.Fatalf("client %d got %d %q, want 200 %q", i, codes[i], bodies[i], bodies[0])
		}
	}
}

// With ?target= the agent cannot change the bytes, so nine client families
// share one entry and one render instead of nine.
func TestExplicitTargetIsNotSplitByAgent(t *testing.T) {
	s, _, path := flightShareServer(t)
	var renders atomic.Int64
	s.subscriptionRender = flightRender(s, &renders, nil)
	for _, ua := range []string{"clash-verge/v2", "Stash/2", "Surge/5", "curl/8", "sing-box", "Shadowrocket/2", "Loon/3", "Quantumult X", "Egern/1"} {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(path+"?target=ClashMeta", ua))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", ua, rec.Code)
		}
	}
	if renders.Load() != 1 || s.subscriptionCache.Len() != 1 {
		t.Fatalf("renders = %d, entries = %d, want 1 and 1", renders.Load(), s.subscriptionCache.Len())
	}
}

// A client that hangs up mid-render does not waste the render: it still
// lands in the cache for the next request.
func TestAnEndedRequestDoesNotCancelTheSharedRender(t *testing.T) {
	s, _, path := flightShareServer(t)
	var renders atomic.Int64
	gate := make(chan struct{})
	s.subscriptionRender = flightRender(s, &renders, gate)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(path, "curl/8").WithContext(ctx))
		done <- rec.Code
	}()
	for renders.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if code := <-done; code != http.StatusNotFound {
		t.Fatalf("ended request answered %d, want the decoy", code)
	}
	close(gate)
	deadline := time.Now().Add(10 * time.Second)
	for s.subscriptionCache.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the shared render never reached the cache")
		}
		time.Sleep(time.Millisecond)
	}
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	if rec.Code != http.StatusOK || renders.Load() != 1 {
		t.Fatalf("follow-up answered %d after %d renders, want a cache hit after 1", rec.Code, renders.Load())
	}
}

// A cached body rendered from any snapshot other than the one stored now is
// a miss, even with TTL left.
func TestCachedBodyFromAnotherContentVersionIsAMiss(t *testing.T) {
	s, _, path := flightShareServer(t)
	var renders atomic.Int64
	s.subscriptionRender = flightRender(s, &renders, nil)
	key := subscriptionCacheKey{ShareID: "s1", Format: "base64", UAClass: "other"}
	s.subscriptionCache.PutSnapshot(key, []byte("rendered from older content"), "text/plain", "", subscriptionContentHash("older"), "", false, s.now(), s.now())
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "older") || renders.Load() != 1 {
		t.Fatalf("served %d %q after %d renders", rec.Code, rec.Body.String(), renders.Load())
	}
}

// A core share reads the user's state on every request, so suspending the
// user takes effect on the next fetch instead of after the cache's 30 minutes.
func TestCoreShareReflectsASuspensionOnTheNextFetch(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy node profile not found")
	}
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
	subURL := publishProxyUserShare(t, st, "alice", "alice-team", "sub-token-secret-abcdefghijklmnopqrstuvwxyz")
	fetch := func() int {
		req := httptest.NewRequest(http.MethodGet, subURL+"?format=plain", nil)
		req.RemoteAddr = "192.0.2.60:4000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := fetch(); code != http.StatusOK {
		t.Fatalf("active user answered %d", code)
	}
	alice, ok := st.ProxyUser("alice")
	if !ok {
		t.Fatal("alice not found")
	}
	alice.Enabled = false
	alice.Status = model.ProxyUserStatusDisabled
	if err := st.UpsertProxyUser(alice); err != nil {
		t.Fatal(err)
	}
	if code := fetch(); code != http.StatusNotFound {
		t.Fatalf("suspended user answered %d on the next fetch, want the decoy", code)
	}
}

// A refresh that brings back the bytes already served must not cost a render.
// Before, every committed refresh bumped the publication epoch, the extend
// path refused the new epoch, and each poll after the refresh interval paid a
// provider fetch plus a full render of identical bytes.
func TestAnUnchangedRefreshExtendsInsteadOfRendering(t *testing.T) {
	s, _, path := flightShareServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	var renders, fetches atomic.Int64
	s.subscriptionRender = flightRender(s, &renders, nil)
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetches.Add(1)
		return model.SubscriptionSnapshot{Raw: "nodes"}, nil
	}
	fetch := func() string {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		return rec.Body.String()
	}
	first := fetch()
	now = now.Add(subscriptionCacheTTL + time.Minute)
	if got := fetch(); got != first {
		t.Fatalf("body changed across an identical refresh: %q then %q", first, got)
	}
	if fetches.Load() != 1 || renders.Load() != 1 {
		t.Fatalf("fetches = %d, renders = %d, want one refresh and no second render", fetches.Load(), renders.Load())
	}
	publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "rec"})
	publication.mu.Lock()
	epoch := publication.epoch
	publication.mu.Unlock()
	if epoch != 0 {
		t.Fatalf("an unchanged refresh published epoch %d", epoch)
	}
}

// During an outage only the first failure publishes (the body turns into the
// last good one, marked stale). Later retries change only the retry time and
// must not throw away the stale body each time.
func TestOutageRetriesDoNotRepublishTheStaleBody(t *testing.T) {
	s, _, path := flightShareServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	var renders, fetches atomic.Int64
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		renders.Add(1)
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("last good"), Stale: snap.Stale, RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetches.Add(1)
		return model.SubscriptionSnapshot{}, context.DeadlineExceeded
	}
	fetch := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
		return rec
	}
	now = now.Add(subscriptionRefreshInterval + time.Minute)
	if rec := fetch(); rec.Code != http.StatusOK || rec.Header().Get("X-Lattice-Subscription-Stale") != "true" {
		t.Fatalf("first outage fetch answered %d stale=%q", rec.Code, rec.Header().Get("X-Lattice-Subscription-Stale"))
	}
	rendersAfterFirst := renders.Load()
	for i := 0; i < 3; i++ {
		now = now.Add(subscriptionStaleRetryInterval + time.Second)
		if rec := fetch(); rec.Code != http.StatusOK || rec.Header().Get("X-Lattice-Subscription-Stale") != "true" {
			t.Fatalf("retry %d answered %d stale=%q", i, rec.Code, rec.Header().Get("X-Lattice-Subscription-Stale"))
		}
	}
	if fetches.Load() != 4 || renders.Load() != rendersAfterFirst {
		t.Fatalf("fetches = %d, renders = %d (after first %d); retries must not re-render", fetches.Load(), renders.Load(), rendersAfterFirst)
	}
}

// One valid link can ask for dozens of variants, each a plugin render on a
// pool of two workers. Past its render budget a link's new variants answer
// the decoy, while what is already cached keeps being served and other links
// are untouched.
func TestALinkCannotSpendRendersPastItsBudget(t *testing.T) {
	s, st, path := flightShareServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	var renders atomic.Int64
	s.subscriptionRender = flightRender(s, &renders, nil)
	otherToken := strings.Repeat("o", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s2", Slug: "other", Token: otherToken, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "rec"}})

	var variants []string
	for target := range subscriptionShareTargets {
		for _, flags := range []string{"", "&includeUnsupportedProxy=1", "&prettyYaml=1", "&includeUnsupportedProxy=1&prettyYaml=1"} {
			variants = append(variants, "?target="+target+flags)
		}
	}
	fetch := func(p string) int {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(p, "curl/8"))
		return rec.Code
	}
	for i := 0; i < shareRenderBudgetBurst; i++ {
		if code := fetch(path + variants[i]); code != http.StatusOK {
			t.Fatalf("variant %d inside the budget answered %d", i, code)
		}
	}
	if code := fetch(path + variants[shareRenderBudgetBurst]); code != http.StatusNotFound {
		t.Fatalf("a render past the budget answered %d, want the decoy", code)
	}
	if code := fetch(path + variants[0]); code != http.StatusOK {
		t.Fatalf("a cached variant answered %d once the budget was spent", code)
	}
	if code := fetch("/sub/other/" + otherToken + variants[shareRenderBudgetBurst]); code != http.StatusOK {
		t.Fatalf("another link answered %d; budgets are per link", code)
	}
	now = now.Add(time.Hour / shareRenderBudgetPerHour)
	if code := fetch(path + variants[shareRenderBudgetBurst]); code != http.StatusOK {
		t.Fatalf("the budget did not refill: %d", code)
	}
	if want := int64(shareRenderBudgetBurst + 2); renders.Load() != want {
		t.Fatalf("renders = %d, want %d", renders.Load(), want)
	}
	s.shareRefusalAudits.Wait()
	found := false
	for _, ev := range st.AuditEvents() {
		if ev.Decision == "deny" && ev.Reason == "subscription_render_budget_exhausted" && ev.Metadata["share_id"] == "s1" {
			found = true
		}
	}
	if !found {
		t.Fatal("the exhausted budget was not audited")
	}
}

// An identity suspended, a credential rotated or a line added changes what a
// record reading vpn-core should serve. The next fetch of any plugin link
// refreshes its snapshot and serves the new content, instead of waiting for
// the snapshot to age past the refresh interval and the cache past its TTL.
func TestAVPNCoreChangeReachesPluginLinksOnTheNextFetch(t *testing.T) {
	s, _, path := flightShareServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	var renders, fetches atomic.Int64
	content := "nodes"
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetches.Add(1)
		return model.SubscriptionSnapshot{Raw: content}, nil
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		renders.Add(1)
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("render of " + snap.Raw), RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	fetch := func() string {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		return rec.Body.String()
	}
	if got := fetch(); got != "render of nodes" || fetches.Load() != 0 {
		t.Fatalf("first fetch %q after %d provider fetches", got, fetches.Load())
	}

	// A change that did not move this record's content costs a refresh and no
	// render: the body it already had is extended.
	s.triggerVPNCoreMutation()
	if got := fetch(); got != "render of nodes" || fetches.Load() != 1 || renders.Load() != 1 {
		t.Fatalf("unchanged content: %q, fetches %d, renders %d", got, fetches.Load(), renders.Load())
	}
	if got := fetch(); got != "render of nodes" || fetches.Load() != 1 {
		t.Fatalf("the refreshed source was refreshed again: fetches %d", fetches.Load())
	}

	// A change that moved it is served on the next fetch. It comes after a
	// quiet pacing interval, so it advances the generation at once.
	content = "nodes without the suspended identity"
	now = now.Add(vpnCoreLinkChangeInterval)
	s.triggerVPNCoreMutation()
	if got := fetch(); got != "render of nodes without the suspended identity" || renders.Load() != 2 {
		t.Fatalf("moved content: %q after %d renders", got, renders.Load())
	}
}

// A render that was already running when the fleet changed was built from
// the old export. It may answer the request that started it, but it must not
// be reused for a TTL: the next fetch revalidates.
func TestARenderOvertakenByAVPNCoreChangeIsNotReused(t *testing.T) {
	s, _, path := flightShareServer(t)
	var fetches atomic.Int64
	content := "before"
	if err := s.store.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "rec", Raw: content, FetchedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetches.Add(1)
		return model.SubscriptionSnapshot{Raw: content}, nil
	}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		blocked := false
		once.Do(func() { blocked = true; close(started) })
		if blocked {
			<-release
		}
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("render of " + snap.Raw), RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	done := make(chan string, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
		done <- rec.Body.String()
	}()
	<-started
	content = "after"
	s.triggerVPNCoreMutation()
	close(release)
	<-done
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	if rec.Body.String() != "render of after" || fetches.Load() != 1 {
		t.Fatalf("follow-up served %q after %d provider fetches, want the new content after one", rec.Body.String(), fetches.Load())
	}
}
