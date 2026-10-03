package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// fleetLinkServer is a plugin link whose provider returns *content (or
// fails while *fail is set) and whose render echoes the snapshot.
func fleetLinkServer(t *testing.T, content *string, fail *bool) (*Server, string, *time.Time, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	s, _, path := flightShareServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	var renders, fetches atomic.Int64
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		fetches.Add(1)
		if *fail {
			return model.SubscriptionSnapshot{}, context.DeadlineExceeded
		}
		return model.SubscriptionSnapshot{Raw: *content}, nil
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		renders.Add(1)
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("render of " + snap.Raw), Stale: snap.Stale, RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	return s, path, &now, &renders, &fetches
}

func fleetFetch(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	return rec
}

// A bulk import or a quota sweep commits many vpn-core writes in a row.
// Advancing the generation per write cost each polled source one provider
// fetch per write. The first write still reaches links at once; the rest of
// the burst is held and lands on the first fetch after the pacing interval,
// so the burst costs the source two refreshes, not one per write.
func TestABurstOfVPNCoreChangesRefreshesASourceOncePerInterval(t *testing.T) {
	content, fail := "nodes", false
	s, path, now, renders, fetches := fleetLinkServer(t, &content, &fail)
	if got := fleetFetch(t, s, path).Body.String(); got != "render of nodes" || fetches.Load() != 0 {
		t.Fatalf("first fetch %q after %d provider fetches", got, fetches.Load())
	}

	content = "nodes after the first write"
	s.triggerVPNCoreMutation()
	if got := fleetFetch(t, s, path).Body.String(); got != "render of nodes after the first write" || fetches.Load() != 1 {
		t.Fatalf("the first write of a burst did not reach the link: %q after %d provider fetches", got, fetches.Load())
	}

	for i := 0; i < 20; i++ {
		*now = now.Add(time.Second)
		content = "nodes after the whole burst"
		s.triggerVPNCoreMutation()
		if got := fleetFetch(t, s, path).Body.String(); got != "render of nodes after the first write" {
			t.Fatalf("write %d inside the interval was applied early: %q", i, got)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("provider fetches = %d during the burst, want none past the first", fetches.Load())
	}

	*now = now.Add(vpnCoreLinkChangeInterval)
	if got := fleetFetch(t, s, path).Body.String(); got != "render of nodes after the whole burst" || fetches.Load() != 2 {
		t.Fatalf("the held writes did not land after the interval: %q after %d provider fetches", got, fetches.Load())
	}
	if got := fleetFetch(t, s, path).Body.String(); got != "render of nodes after the whole burst" || fetches.Load() != 2 || renders.Load() != 3 {
		t.Fatalf("a settled burst kept refreshing: %q, fetches %d, renders %d", got, fetches.Load(), renders.Load())
	}
}

// A source refreshed only because a vpn-core change made it due must not be
// turned stale by a failed provider fetch. Before, that failure re-rendered
// every share of the source with the stale marker and retried the provider
// every stale-retry interval for as long as the link was polled.
func TestAFailedRevalidationAfterAVPNCoreChangeKeepsTheSnapshotFresh(t *testing.T) {
	content, fail := "nodes", false
	s, path, now, renders, fetches := fleetLinkServer(t, &content, &fail)
	fleetFetch(t, s, path)

	fail = true
	s.triggerVPNCoreMutation()
	rec := fleetFetch(t, s, path)
	if rec.Body.String() != "render of nodes" || rec.Header().Get("X-Lattice-Subscription-Stale") != "" || fetches.Load() != 1 || renders.Load() != 1 {
		t.Fatalf("failed revalidation served %q stale=%q after %d fetches and %d renders",
			rec.Body.String(), rec.Header().Get("X-Lattice-Subscription-Stale"), fetches.Load(), renders.Load())
	}
	for i := 0; i < 3; i++ {
		*now = now.Add(subscriptionStaleRetryInterval + time.Second)
		fleetFetch(t, s, path)
	}
	if fetches.Load() != 1 {
		t.Fatalf("provider fetches = %d; a settled failed revalidation must not retry until the next change", fetches.Load())
	}
	snap, ok := s.store.SubscriptionSnapshot("p", "rec")
	if !ok || snap.Stale || snap.FetchError != "" {
		t.Fatalf("snapshot after a failed revalidation = %+v", snap)
	}
	publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "rec"})
	publication.mu.Lock()
	epoch := publication.epoch
	publication.mu.Unlock()
	if epoch != 0 {
		t.Fatalf("a failed revalidation published epoch %d", epoch)
	}

	// The next change tries again, and the provider being back serves it.
	fail = false
	content = "nodes once the provider is back"
	*now = now.Add(vpnCoreLinkChangeInterval)
	s.triggerVPNCoreMutation()
	if got := fleetFetch(t, s, path).Body.String(); got != "render of nodes once the provider is back" || fetches.Load() != 2 {
		t.Fatalf("the next change was not served: %q after %d fetches", got, fetches.Load())
	}

	// A snapshot past its refresh interval still turns stale on failure.
	fail = true
	*now = now.Add(subscriptionRefreshInterval + time.Minute)
	if rec := fleetFetch(t, s, path); rec.Header().Get("X-Lattice-Subscription-Stale") != "true" {
		t.Fatalf("an aged snapshot's failed refresh was not marked stale")
	}
}
