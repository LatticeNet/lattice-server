package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The rendered-body cache must drop entries the moment their inputs move:
// a provider refresh that returned different bytes (source invalidation), or
// an operator edit through the plugin's management API (plugin invalidation).
// TTL is only the revalidation cadence; change is the real invalidator.
func TestShareCacheInvalidationBySourceAndPlugin(t *testing.T) {
	s, st := newShareTestServer(t)
	base := s.now()
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "s1", Slug: "one", Token: "t1", Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "latticenet.sub-store", SubscriptionID: "sub-a"},
	})
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "s2", Slug: "two", Token: "t2", Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "latticenet.sub-store", SubscriptionID: "sub-b"},
	})
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "s3", Slug: "three", Token: "t3", Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "latticenet.other", SubscriptionID: "sub-a"},
	})

	put := func(id string) {
		s.subscriptionCache.Put(subscriptionCacheKey{ShareID: id, Format: "base64", UAClass: "surge"}, []byte("x"), "text/plain", "", "h", base)
	}
	put("s1")
	put("s2")
	put("s3")

	// A content change on sub-a drops exactly the shares sourcing it.
	s.invalidateSharesForSource("latticenet.sub-store", "sub-a")
	if _, ok := s.subscriptionCache.GetStale(subscriptionCacheKey{ShareID: "s1", Format: "base64", UAClass: "surge"}); ok {
		t.Fatal("s1 survived its source's content change")
	}
	for _, id := range []string{"s2", "s3"} {
		if _, ok := s.subscriptionCache.GetStale(subscriptionCacheKey{ShareID: id, Format: "base64", UAClass: "surge"}); !ok {
			t.Fatalf("%s was dropped by an unrelated source change", id)
		}
	}

	// A store mutation through the plugin's management API drops every share
	// sourcing that plugin, and no one else's.
	s.invalidateSharesForPlugin("latticenet.sub-store")
	if _, ok := s.subscriptionCache.GetStale(subscriptionCacheKey{ShareID: "s2", Format: "base64", UAClass: "surge"}); ok {
		t.Fatal("s2 survived its plugin's store mutation")
	}
	if _, ok := s.subscriptionCache.GetStale(subscriptionCacheKey{ShareID: "s3", Format: "base64", UAClass: "surge"}); !ok {
		t.Fatal("s3 was dropped by another plugin's mutation")
	}
}

var _ = time.Minute // keep the import if the file grows a TTL case
