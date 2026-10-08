package server

import (
	"bytes"
	"strconv"
	"testing"
	"time"
)

func byteCacheKey(i int) subscriptionCacheKey {
	return subscriptionCacheKey{ShareID: "share-" + strconv.Itoa(i), Format: "base64", UAClass: "other"}
}

// The serve caches are bounded by what their bodies weigh, not by how many
// there are: more than 512 small bodies stay cached under the byte cap.
func TestShareBodyCachesAreSizedByBytesNotEntries(t *testing.T) {
	srv, _ := newServerForPluginHost(t)
	for name, c := range map[string]*subscriptionCache{"share": srv.subscriptionCache, "identity": srv.identityLinkCache} {
		if c.maxBytes != 64<<20 || c.entryOverhead != subscriptionCacheEntryOverhead {
			t.Fatalf("%s cache: maxBytes=%d overhead=%d, want 64 MiB and the per-entry overhead", name, c.maxBytes, c.entryOverhead)
		}
		now := time.Now()
		for i := range 600 {
			c.Put(byteCacheKey(i), []byte("vless://placeholder-"+strconv.Itoa(i)), "text/plain", "", "v", now)
		}
		if c.Len() != 600 {
			t.Fatalf("%s cache holds %d of 600 small bodies; an entry count is evicting", name, c.Len())
		}
		if _, _, _, ok := c.Get(byteCacheKey(0), now); !ok {
			t.Fatalf("%s cache evicted the first small body", name)
		}
	}
}

// Eviction is by bytes, least recently used first, and one large body can
// push out several small ones.
func TestByteSizedShareCacheEvictsByBytes(t *testing.T) {
	now := time.Now()
	body := func(n int) []byte { return bytes.Repeat([]byte("b"), n) }
	size := func(c *subscriptionCache, i, n int) int {
		key := byteCacheKey(i)
		return subscriptionCacheEntrySize(subscriptionCacheEntry{key: key, body: body(n), contentType: "text/plain", revalidationVersion: "v"}) + c.entryOverhead
	}
	probe := newSubscriptionByteCache(1, time.Minute)
	limit := size(probe, 0, 1000) * 3
	c := newSubscriptionByteCache(limit, time.Minute)

	for i := range 3 {
		c.Put(byteCacheKey(i), body(1000), "text/plain", "", "v", now)
	}
	if c.Len() != 3 || c.bytes != limit {
		t.Fatalf("three bodies at the cap: entries=%d bytes=%d cap=%d", c.Len(), c.bytes, limit)
	}
	// Touch 0, so 1 is now the least recently used.
	if _, _, _, ok := c.Get(byteCacheKey(0), now); !ok {
		t.Fatal("body 0 missing")
	}
	c.Put(byteCacheKey(3), body(1000), "text/plain", "", "v", now)
	if _, _, _, ok := c.Get(byteCacheKey(1), now); ok {
		t.Fatal("the least recently used body survived an insert past the byte cap")
	}
	for _, i := range []int{0, 2, 3} {
		if _, _, _, ok := c.Get(byteCacheKey(i), now); !ok {
			t.Fatalf("body %d was evicted although the cap had room after one eviction", i)
		}
	}
	// One body as large as two small ones evicts the two oldest.
	big := 2*size(c, 4, 1000) - size(c, 4, 0)
	c.Put(byteCacheKey(4), body(big), "text/plain", "", "v", now)
	if c.bytes > limit {
		t.Fatalf("cache holds %d bytes over its %d cap", c.bytes, limit)
	}
	if c.Len() != 2 {
		t.Fatalf("after a double-size body the cache holds %d entries, want 2", c.Len())
	}
	if _, _, _, ok := c.Get(byteCacheKey(4), now); !ok {
		t.Fatal("the large body was not cached")
	}
	// A body larger than the whole cap is not cached and evicts nothing.
	before := c.Len()
	c.Put(byteCacheKey(5), body(limit), "text/plain", "", "v", now)
	if c.Len() != before {
		t.Fatalf("an oversized body changed the cache from %d to %d entries", before, c.Len())
	}
}
