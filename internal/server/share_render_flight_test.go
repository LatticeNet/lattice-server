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
