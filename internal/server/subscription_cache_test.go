package server

import (
	"strings"
	"testing"
	"time"
	"unsafe"
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
	keyA, keyB := shareCacheKey("a"), shareCacheKey("b")
	sizeA := subscriptionCacheEntrySize(subscriptionCacheEntry{key: keyA, body: []byte("123"), contentType: "text/plain", userinfo: "ui", revalidationVersion: "private", publicSourceVersion: "sv1"})
	sizeB := subscriptionCacheEntrySize(subscriptionCacheEntry{key: keyB, body: []byte("45"), contentType: "text/plain"})
	c.maxBytes = sizeA + sizeB
	c.PutSnapshot(keyA, []byte("123"), "text/plain", "ui", "private", "sv1", false, time.Time{}, base)
	c.Put(keyB, []byte("45"), "text/plain", "", "", base)
	c.PutSnapshot(keyA, []byte("1"), "text/plain", "ui", "private", "sv1", false, time.Time{}, base)
	want := subscriptionCacheEntrySize(subscriptionCacheEntry{key: keyA, body: []byte("1"), contentType: "text/plain", userinfo: "ui", revalidationVersion: "private", publicSourceVersion: "sv1"}) + sizeB
	if c.bytes != want || c.Len() != 2 {
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
	key := shareCacheKey("a")
	capSize := subscriptionCacheEntrySize(subscriptionCacheEntry{key: key, body: []byte("abc"), contentType: "text/plain"})
	c.maxBytes = capSize
	body := []byte("abc")
	c.Put(key, body, "text/plain", "", "", base)
	body[0] = 'x'
	got, _, _, ok := c.Get(key, base)
	if !ok || string(got) != "abc" {
		t.Fatalf("cache retained caller alias: %q %v", got, ok)
	}
	c.Put(key, []byte("abcd"), "text/plain", "", "", base)
	if _, _, _, ok := c.Get(key, base); ok || c.bytes != 0 {
		t.Fatalf("oversized replacement remained cached: bytes=%d", c.bytes)
	}
}

func TestSubscriptionCacheAccountsEveryVariableByteAtExactCap(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	key := subscriptionCacheKey{ShareID: "share", Format: "plain", UAClass: "surge"}
	entry := subscriptionCacheEntry{key: key, body: []byte("body"), contentType: "application/json", userinfo: "upload=1", revalidationVersion: "private-hash", publicSourceVersion: "sv1:public"}
	size := subscriptionCacheEntrySize(entry)
	for _, tc := range []struct {
		name string
		cap  int
		want bool
	}{{"exact cap", size, true}, {"cap minus one", size - 1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			c := newSubscriptionCache(8, time.Minute)
			c.maxBytes = tc.cap
			c.PutSnapshot(key, entry.body, entry.contentType, entry.userinfo, entry.revalidationVersion, entry.publicSourceVersion, false, time.Time{}, base)
			_, ok := c.GetStale(key)
			if ok != tc.want || c.bytes > tc.cap {
				t.Fatalf("cached=%v bytes=%d cap=%d", ok, c.bytes, tc.cap)
			}
		})
	}
}

func TestSubscriptionCacheIndexUsesTheAccountedStoredKeyBacking(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	backing := strings.Repeat("x", 4096)
	key := subscriptionCacheKey{ShareID: backing[10:42], Format: backing[100:132], UAClass: backing[200:232]}
	c := newSubscriptionCache(8, time.Minute)
	c.PutSnapshot(key, []byte("body"), "text/plain", "userinfo", "private", "public", false, base, base)
	if len(c.entries) != 1 {
		t.Fatalf("entries=%d", len(c.entries))
	}
	for storedKey, el := range c.entries {
		entry := el.Value.(*subscriptionCacheEntry)
		if unsafe.StringData(storedKey.ShareID) != unsafe.StringData(entry.key.ShareID) ||
			unsafe.StringData(storedKey.Format) != unsafe.StringData(entry.key.Format) ||
			unsafe.StringData(storedKey.UAClass) != unsafe.StringData(entry.key.UAClass) {
			t.Fatal("map index and accounted entry retain different key backing")
		}
		if unsafe.StringData(storedKey.ShareID) == unsafe.StringData(key.ShareID) ||
			unsafe.StringData(storedKey.Format) == unsafe.StringData(key.Format) ||
			unsafe.StringData(storedKey.UAClass) == unsafe.StringData(key.UAClass) {
			t.Fatal("cache index retained caller key backing")
		}
		if c.bytes != entry.size || entry.size != subscriptionCacheEntrySize(*entry) {
			t.Fatalf("stored key backing not exactly accounted: cache=%d entry=%d recomputed=%d", c.bytes, entry.size, subscriptionCacheEntrySize(*entry))
		}
	}
}

func TestSubscriptionCacheMetadataCannotBypassByteBudget(t *testing.T) {
	c := newSubscriptionCache(8, time.Minute)
	key := shareCacheKey("a")
	c.maxBytes = subscriptionCacheEntrySize(subscriptionCacheEntry{key: key, body: []byte("x"), contentType: "text/plain"})
	c.PutSnapshot(key, []byte("x"), "text/plain", "oversized-userinfo", "private", "public", false, time.Time{}, time.Now())
	if c.Len() != 0 || c.bytes != 0 {
		t.Fatalf("metadata-heavy entry bypassed cap: entries=%d bytes=%d", c.Len(), c.bytes)
	}
}

func TestSubscriptionCacheExtendRejectsReplacedRevision(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	c := newSubscriptionCache(8, time.Minute)
	key := shareCacheKey("a")
	c.PutSnapshot(key, []byte("old"), "text/plain", "old-ui", "old-private", "old-public", true, base, base)
	old, _ := c.GetStale(key)
	c.PutSnapshot(key, []byte("new"), "text/plain", "new-ui", "new-private", "new-public", false, base.Add(time.Second), base)
	if c.ExtendSnapshot(key, old.revision, "stale-ui", "stale-public", true, base, base.Add(time.Minute)) {
		t.Fatal("stale revalidation mutated a replacement entry")
	}
	got, _ := c.GetStale(key)
	if string(got.body) != "new" || got.userinfo != "new-ui" || got.publicSourceVersion != "new-public" || got.stale {
		t.Fatalf("replacement was stamped with old metadata: %+v", got)
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
	if !ok || string(stale.body) != "body-a" || stale.revalidationVersion != "hash-1" {
		t.Fatalf("stale entry = %q %q %v", stale.body, stale.revalidationVersion, ok)
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
	if !ok || string(stale.body) != "new" || stale.revalidationVersion != "hash-2" {
		t.Fatalf("replaced entry = %q %q %v", stale.body, stale.revalidationVersion, ok)
	}
}
