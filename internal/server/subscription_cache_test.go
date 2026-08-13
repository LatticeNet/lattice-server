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

	c.Put(shareCacheKey("a"), []byte("body-a"), "text/plain", "", "", base)

	body, ct, _, ok := c.Get(shareCacheKey("a"), base.Add(30*time.Second))
	if !ok || string(body) != "body-a" || ct != "text/plain" {
		t.Fatalf("fresh entry not served: %q %q %v", body, ct, ok)
	}
	if _, _, _, ok := c.Get(shareCacheKey("a"), base.Add(2*time.Minute)); ok {
		t.Fatal("entry served after its TTL")
	}
}

func TestSubscriptionCacheIsBounded(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(2, time.Minute)

	c.Put(shareCacheKey("x"), []byte("x"), "text/plain", "", "", base)
	c.Put(shareCacheKey("y"), []byte("y"), "text/plain", "", "", base)
	c.Put(shareCacheKey("z"), []byte("z"), "text/plain", "", "", base)

	if c.Len() > 2 {
		t.Fatalf("cache holds %d entries, cap is 2", c.Len())
	}
	if _, _, _, ok := c.Get(shareCacheKey("x"), base); ok {
		t.Fatal("the oldest entry was kept; eviction must drop it")
	}
	if _, _, _, ok := c.Get(shareCacheKey("z"), base); !ok {
		t.Fatal("the newest entry was evicted")
	}
}

func TestSubscriptionCacheBoundsBytesAndAccountsForReplacement(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	c.maxBytes = 5
	c.Put(shareCacheKey("a"), []byte("123"), "text/plain", "", "", base)
	c.Put(shareCacheKey("b"), []byte("45"), "text/plain", "", "", base)
	c.Put(shareCacheKey("a"), []byte("1"), "text/plain", "", "", base)
	if c.bytes != 3 || c.Len() != 2 {
		t.Fatalf("replacement accounting bytes=%d entries=%d", c.bytes, c.Len())
	}
	c.Put(shareCacheKey("c"), []byte("678"), "text/plain", "", "", base)
	if c.bytes > c.maxBytes || c.Len() != 2 {
		t.Fatalf("byte eviction bytes=%d entries=%d", c.bytes, c.Len())
	}
	if _, _, _, ok := c.Get(shareCacheKey("b"), base); ok {
		t.Fatal("least-recent byte-budget entry was not evicted")
	}
}

func TestSubscriptionCacheBypassesOversizedAndCopiesBodies(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	c.maxBytes = 3
	body := []byte("abc")
	c.Put(shareCacheKey("a"), body, "text/plain", "", "", base)
	body[0] = 'x'
	got, _, _, ok := c.Get(shareCacheKey("a"), base)
	if !ok || string(got) != "abc" {
		t.Fatalf("cache retained caller alias: %q %v", got, ok)
	}
	c.Put(shareCacheKey("a"), []byte("oversized"), "text/plain", "", "", base)
	if _, _, _, ok := c.Get(shareCacheKey("a"), base); ok || c.bytes != 0 {
		t.Fatalf("oversized replacement remained cached: bytes=%d", c.bytes)
	}
}

// An empty body must never become something the cache can hand back later: the
// endpoint refuses to serve one, so storing it would create a path back to the
// exact response that wipes a client's nodes.
func TestSubscriptionCacheNeverStoresEmptyBodies(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(4, time.Minute)

	c.Put(shareCacheKey("a"), nil, "text/plain", "", "", base)
	if _, _, _, ok := c.Get(shareCacheKey("a"), base); ok {
		t.Fatal("a nil body was cached")
	}
	c.Put(shareCacheKey("a"), []byte{}, "text/plain", "", "", base)
	if _, _, _, ok := c.Get(shareCacheKey("a"), base); ok {
		t.Fatal("an empty body was cached")
	}
}

// Different formats and different client classes are different bodies, so they
// must not collide on one entry.
func TestSubscriptionCacheKeysOnFormatAndUAClass(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)

	c.Put(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, []byte("b64-surge"), "text/plain", "", "", base)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "surge"}, []byte("plain-surge"), "text/plain", "", "", base)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "loon"}, []byte("b64-loon"), "text/plain", "", "", base)

	for _, tc := range []struct {
		key  subscriptionCacheKey
		want string
	}{
		{subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, "b64-surge"},
		{subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "surge"}, "plain-surge"},
		{subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "loon"}, "b64-loon"},
	} {
		body, _, _, ok := c.Get(tc.key, base)
		if !ok || string(body) != tc.want {
			t.Fatalf("key %+v served %q (ok=%v), want %q", tc.key, body, ok, tc.want)
		}
	}
}

func TestSubscriptionCacheInvalidateShareDropsEveryFormat(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, []byte("x"), "text/plain", "", "", base)
	c.Put(subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "loon"}, []byte("y"), "text/plain", "", "", base)
	c.Put(subscriptionCacheKey{ShareID: "b", Format: "base64", UAClass: "surge"}, []byte("z"), "text/plain", "", "", base)

	c.InvalidateShare("a")

	if _, _, _, ok := c.Get(subscriptionCacheKey{ShareID: "a", Format: "base64", UAClass: "surge"}, base); ok {
		t.Fatal("invalidated share still cached")
	}
	if _, _, _, ok := c.Get(subscriptionCacheKey{ShareID: "a", Format: "plain", UAClass: "loon"}, base); ok {
		t.Fatal("invalidation missed a second format")
	}
	if _, _, _, ok := c.Get(subscriptionCacheKey{ShareID: "b", Format: "base64", UAClass: "surge"}, base); !ok {
		t.Fatal("invalidation removed an unrelated share")
	}
}

// The provider's traffic figures travel with the body. If they lived in a
// parallel map, a hit could pair one subscription's nodes with another's
// remaining-quota numbers.
func TestSubscriptionCacheCarriesUserinfoWithTheBody(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	c.Put(shareCacheKey("a"), []byte("a"), "text/plain", "upload=1; download=2; total=3", "", base)
	c.Put(shareCacheKey("b"), []byte("b"), "text/plain", "upload=9", "", base)

	_, _, ua, ok := c.Get(shareCacheKey("a"), base)
	if !ok || ua != "upload=1; download=2; total=3" {
		t.Fatalf("userinfo for a = %q (ok=%v)", ua, ok)
	}
	_, _, ub, ok := c.Get(shareCacheKey("b"), base)
	if !ok || ub != "upload=9" {
		t.Fatalf("userinfo for b = %q (ok=%v)", ub, ok)
	}
}

func TestSubscriptionCacheRevalidationExtendsUnchangedBody(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	key := shareCacheKey("a")
	c.Put(key, []byte("body-a"), "text/plain", "ui", "hash-1", base)

	// Past expiry the plain Get misses, but the stale entry is still readable
	// for the revalidation decision.
	if _, _, _, ok := c.Get(key, base.Add(2*time.Minute)); ok {
		t.Fatal("expired entry served without revalidation")
	}
	stale, ok := c.GetStale(key)
	if !ok || string(stale.body) != "body-a" || stale.contentVersion != "hash-1" {
		t.Fatalf("stale entry = %q %q %v", stale.body, stale.contentVersion, ok)
	}

	// The serve path's "hash still matches" branch: extend, and the entry
	// serves again for a full TTL from the extension.
	c.Extend(key, base.Add(2*time.Minute))
	body, _, ui, ok := c.Get(key, base.Add(2*time.Minute+30*time.Second))
	if !ok || string(body) != "body-a" || ui != "ui" {
		t.Fatalf("extended entry not served: %q %q %v", body, ui, ok)
	}
}

func TestSubscriptionCacheGettersReturnDefensiveBodyCopies(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	key := shareCacheKey("a")
	c.Put(key, []byte("body"), "text/plain", "", "v1", base)
	fresh, _, _, _ := c.Get(key, base)
	fresh[0] = 'x'
	stale, _ := c.GetStale(key)
	stale.body[1] = 'y'
	again, _, _, _ := c.Get(key, base)
	if string(again) != "body" {
		t.Fatalf("getter mutation rewrote cached body: %q", again)
	}
}

func TestSubscriptionCacheHashChangeForcesReplace(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	key := shareCacheKey("a")
	c.Put(key, []byte("old"), "text/plain", "", "hash-1", base)

	// The "hash moved" branch re-renders and Puts under the new hash; a later
	// revalidation against the old hash must not resurrect the old body.
	c.Put(key, []byte("new"), "text/plain", "", "hash-2", base.Add(2*time.Minute))
	stale, ok := c.GetStale(key)
	if !ok || string(stale.body) != "new" || stale.contentVersion != "hash-2" {
		t.Fatalf("replaced entry = %q %q %v", stale.body, stale.contentVersion, ok)
	}
}
