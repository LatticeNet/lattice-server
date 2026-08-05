package server

import (
	"testing"
	"time"
)

func shareCacheKey(id string) subscriptionCacheKey {
	return subscriptionCacheKey{ShareID: id, Format: "base64", UAClass: "surge"}
}

func TestSubscriptionCacheServesFreshAndExpires(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)

	c.Put(shareCacheKey("a"), []byte("body-a"), "text/plain", base)

	body, ct, ok := c.Get(shareCacheKey("a"), base.Add(30*time.Second))
	if !ok || string(body) != "body-a" || ct != "text/plain" {
		t.Fatalf("fresh entry not served: %q %q %v", body, ct, ok)
	}
	if _, _, ok := c.Get(shareCacheKey("a"), base.Add(2*time.Minute)); ok {
		t.Fatal("entry served after its TTL")
	}
}

func TestSubscriptionCacheIsBounded(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(2, time.Minute)

	c.Put(shareCacheKey("x"), []byte("x"), "text/plain", base)
	c.Put(shareCacheKey("y"), []byte("y"), "text/plain", base)
	c.Put(shareCacheKey("z"), []byte("z"), "text/plain", base)

	if c.Len() > 2 {
		t.Fatalf("cache holds %d entries, cap is 2", c.Len())
	}
	if _, _, ok := c.Get(shareCacheKey("x"), base); ok {
		t.Fatal("the oldest entry was kept; eviction must drop it")
	}
	if _, _, ok := c.Get(shareCacheKey("z"), base); !ok {
		t.Fatal("the newest entry was evicted")
	}
}

// An empty body must never become something the cache can hand back later: the
// endpoint refuses to serve one, so storing it would create a path back to the
// exact response that wipes a client's nodes.
func TestSubscriptionCacheNeverStoresEmptyBodies(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(4, time.Minute)

	c.Put(shareCacheKey("a"), nil, "text/plain", base)
	if _, _, ok := c.Get(shareCacheKey("a"), base); ok {
		t.Fatal("a nil body was cached")
	}
	c.Put(shareCacheKey("a"), []byte{}, "text/plain", base)
	if _, _, ok := c.Get(shareCacheKey("a"), base); ok {
		t.Fatal("an empty body was cached")
	}
}

// Different formats and different client classes are different bodies, so they
// must not collide on one entry.
func TestSubscriptionCacheKeysOnFormatAndUAClass(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)

	c.Put(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, []byte("b64-surge"), "text/plain", base)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "surge"}, []byte("plain-surge"), "text/plain", base)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "loon"}, []byte("b64-loon"), "text/plain", base)

	for _, tc := range []struct {
		key  subscriptionCacheKey
		want string
	}{
		{subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, "b64-surge"},
		{subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "surge"}, "plain-surge"},
		{subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "loon"}, "b64-loon"},
	} {
		body, _, ok := c.Get(tc.key, base)
		if !ok || string(body) != tc.want {
			t.Fatalf("key %+v served %q (ok=%v), want %q", tc.key, body, ok, tc.want)
		}
	}
}

func TestSubscriptionCacheInvalidateShareDropsEveryFormat(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, []byte("x"), "text/plain", base)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "loon"}, []byte("y"), "text/plain", base)
	c.Put(subscriptionCacheKey{ShareID: "b", Format: "base64", UAClass: "surge"}, []byte("z"), "text/plain", base)

	c.InvalidateShare("a")

	if _, _, ok := c.Get(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, base); ok {
		t.Fatal("invalidated share still cached")
	}
	if _, _, ok := c.Get(subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "loon"}, base); ok {
		t.Fatal("invalidation missed a second format")
	}
	if _, _, ok := c.Get(subscriptionCacheKey{ShareID: "b", Format: "base64", UAClass: "surge"}, base); !ok {
		t.Fatal("invalidation removed an unrelated share")
	}
}
